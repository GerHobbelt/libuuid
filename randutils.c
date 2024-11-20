/*
 * General purpose random utilities
 *
 * Based on libuuid code.
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "randutils.h"

#ifndef _WIN32

#include <unistd.h>
#include <sys/time.h>
#include <sys/syscall.h>

#ifdef HAVE_TLS
#define THREAD_LOCAL static __thread
#else
#define THREAD_LOCAL static
#endif

#if defined(__linux__) && defined(__NR_gettid)    // && defined(HAVE_JRAND48)
#define DO_JRAND_MIX
THREAD_LOCAL unsigned short ul_jrand_seed[3];
#endif

#ifdef HAVE_SRANDOM
#define srand(x) 	srandom(x)
#define rand() 		random()
#endif

static int get_random_fd(void)
{
	struct timeval	tv;
	static int	fd = -2;
	int		i;

	if (fd == -2) {
		gettimeofday(&tv, 0);
		fd = open("/dev/urandom", O_RDONLY);
		if (fd == -1)
			fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
		if (fd >= 0) {
			i = fcntl(fd, F_GETFD);
			if (i >= 0)
				fcntl(fd, F_SETFD, i | FD_CLOEXEC);
		}
		srand(((unsigned)getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);
#ifdef DO_JRAND_MIX
		ul_jrand_seed[0] = getpid() ^ (tv.tv_sec & 0xFFFF);
		ul_jrand_seed[1] = getppid() ^ (tv.tv_usec & 0xFFFF);
		ul_jrand_seed[2] = (tv.tv_sec ^ tv.tv_usec) >> 16;
#endif
	}
	/* Crank the random number generator a few times */
	gettimeofday(&tv, 0);
	for (i = (tv.tv_sec ^ tv.tv_usec) & 0x1F; i > 0; i--)
		rand();
	return fd;
}


/*
 * Generate a stream of random nbytes into buf.
 * Use /dev/urandom if possible, and if not,
 * use glibc pseudo-random functions.
 */
void get_random_bytes(void *buf, size_t nbytes)
{
	size_t i, n = nbytes;
	int fd;
	int lose_counter = 0;
	unsigned char *cp = buf;

#ifdef HAVE_GETRANDOM
	i = getrandom(buf, nbytes, 0);
	if (i == nbytes)
		return;
#endif
#ifdef HAVE_GETENTROPY
	if (getentropy(buf, nbytes) == 0)
		return;
#endif

	fd = get_random_fd();
	if (fd >= 0) {
		while (n > 0) {
			ssize_t x = read(fd, cp, n);
			if (x <= 0) {
				if (lose_counter++ > 16)
					break;
				continue;
			}
			n -= x;
			cp += x;
			lose_counter = 0;
		}

		close(fd);
	}

	/*
	 * We do this all the time, but this is the only source of
	 * randomness if /dev/random/urandom is out to lunch.
	 */
	for (cp = buf, i = 0; i < nbytes; i++)
		*cp++ ^= (rand() >> 7) & 0xFF;

#ifdef DO_JRAND_MIX
	{
		unsigned short tmp_seed[3];

		memcpy(tmp_seed, ul_jrand_seed, sizeof(tmp_seed));
		ul_jrand_seed[2] = ul_jrand_seed[2] ^ syscall(__NR_gettid);
		for (cp = buf, i = 0; i < nbytes; i++)
			*cp++ ^= (jrand48(tmp_seed) >> 7) & 0xFF;
		memcpy(ul_jrand_seed, tmp_seed,
		       sizeof(ul_jrand_seed)-sizeof(unsigned short));
	}
#endif

	return;
}

#else

#include <winsock2.h>
#include <windows.h>

#include <math.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#pragma intrinsic(__rdtsc)

// https://learn.microsoft.com/en-us/cpp/parallel/thread-local-storage-tls?view=msvc-170
#define THREAD_LOCAL static __declspec( thread ) 

THREAD_LOCAL uint16_t  ul_jrand_seed[3] = { 0 };
THREAD_LOCAL uint16_t  is_initialized = 0;

// --- rand48: copyright Martin Birgmeier 1996. All rights reserved. --------------

#define RAND48_SEED_0   (0x330eu)
#define RAND48_SEED_1   (0xabcdu)
#define RAND48_SEED_2   (0x1234u)
#define RAND48_MULT_0   (0xe66du)
#define RAND48_MULT_1   (0xdeecu)
#define RAND48_MULT_2   (0x0005u)
#define RAND48_ADD      (0x000bu)

THREAD_LOCAL uint16_t _rand48_seed[3] = {
		RAND48_SEED_0,
		RAND48_SEED_1,
		RAND48_SEED_2
};

static inline void
_dorand48(uint16_t xseed[3])
{
	uint32_t  accu;
	uint16_t  temp[2];

	accu = ((uint32_t)RAND48_MULT_0) * (uint32_t)xseed[0] + RAND48_ADD;
	temp[0] = (uint16_t)accu;        /* lower 16 bits */
	accu >>= sizeof(uint16_t) * 8;
	accu += ((uint32_t)RAND48_MULT_0) * (uint32_t)xseed[1] + ((uint32_t)RAND48_MULT_1) * (uint32_t)xseed[0];
	temp[1] = (uint16_t)accu;        /* middle 16 bits */
	accu >>= sizeof(uint16_t) * 8;
	accu += ((uint32_t)RAND48_MULT_0) * (uint32_t)xseed[2] + ((uint32_t)RAND48_MULT_1) * (uint32_t)xseed[1] + ((uint32_t)RAND48_MULT_2) * (uint32_t)xseed[0];
	xseed[0] = temp[0];
	xseed[1] = temp[1];
	xseed[2] = (uint16_t)accu;
}

static inline uint16_t
jrand48(uint16_t xseed[3])
{
	_dorand48(xseed);
	return xseed[1];
}


// QC Hash:

#define M  ((uint64_t)0xC6A4A7935BD1E995ull)
#define R  47 

static inline uint64_t mix(uint64_t v)
	{
		v *= M;
		v ^= v >> R;
		return v * M;
	}


// Based on Murmur2, but simplified, and doesn't require unaligned reads
static inline uint64_t hash(uint64_t h, const void* const data, size_t length)
	{
		const uint8_t * bytes = data;
		//uint64_t h{ H(length) };

		// Mix in `H` bytes worth at a time
		while (length >= sizeof(uint64_t))
		{
			uint64_t w;
			memcpy(&w, bytes, sizeof(uint64_t));

			h *= M;
			h ^= mix(w);

			bytes += sizeof(uint64_t);
			length -= sizeof(uint64_t);
		}

		// Mix in the last few bytes
		if (length != 0)
		{
			uint64_t w = 0u;
			memcpy(&w, bytes, length);

			h *= M;
			h ^= mix(w);
		}

		return h;
	}




static void random_get_base(void)
{
	struct {
		DWORD tid;
		DWORD pid;
		FILETIME ft[4];
	} raw = { 0 };

	raw.tid = GetCurrentThreadId();
	raw.pid = GetCurrentProcessId();

	GetSystemTimes(&raw.ft[0], &raw.ft[1], &raw.ft[2]);

	GetSystemTimeAsFileTime(&raw.ft[3]);

	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
	DWORD buflen = 0;

	DWORD rc = GetLogicalProcessorInformation(NULL, &buflen);
	if (FALSE == rc)
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)calloc(buflen, 1);
			if (NULL != buffer)
			{
				rc = GetLogicalProcessorInformation(buffer, &buflen);
			}
		}
	}

	uint64_t h = 0;
	DWORD datalen = sizeof(raw);

	// hash data
	h = hash(h, &datalen, sizeof(datalen));
	h = hash(h, &raw, datalen);

	if (TRUE == rc)
	{
		// hash buffer
		h = hash(h, &buflen, sizeof(buflen));
		h = hash(h, buffer, buflen);
	}
	if (buffer)
	{
		free(buffer);
	}

	ul_jrand_seed[0] += RAND48_SEED_0 ^ (uint16_t)h;
	h >>= 16;
	ul_jrand_seed[1] += RAND48_SEED_1 ^ (uint16_t)h;
	h >>= 16;
	ul_jrand_seed[2] += RAND48_SEED_2 ^ (uint16_t)h;

	/* Crank the random number generator a few times */
	int i = raw.ft[4].dwLowDateTime & 0x1F;
	for (i += 3; i > 0; i--)
		(void)jrand48(ul_jrand_seed);
}


static inline void quick_rand_seed_update(uint64_t seed)
{
	uint64_t h = 0;
	const DWORD datalen = sizeof(seed);

	// hash data
	h = hash(h, &datalen, sizeof(datalen));
	h = hash(h, &seed, datalen);

	ul_jrand_seed[0] ^= (uint16_t)h;
	h >>= 16;
	ul_jrand_seed[1] ^= (uint16_t)h;
	h >>= 16;
	ul_jrand_seed[2] ^= (uint16_t)h;
	h >>= 16;
	ul_jrand_seed[0] ^= (uint16_t)h;
}


/*
 * Generate a stream of random nbytes into buf.
 */
void random_get_bytes(void* buf, size_t nbytes)
{
	if (!is_initialized) {
		random_get_base();
	}
	is_initialized++;
	// ^^^^^^^^^^^^^   yes, this wraps back to zero and reruns the above code after a while.
	// 
	//                 *THIS IS INTENTIONAL*
	// 
	//                 That's also why the `random_get_base()` code *updates* the rand48 buffer, rather than overwriting it.

	quick_rand_seed_update(__rdtsc());

	{
		uint16_t  tmp_seed[3];

		memcpy(tmp_seed, ul_jrand_seed, sizeof(tmp_seed));
		for (uint8_t *cp = buf, i = 0; i < nbytes; i++)
			*cp++ ^= (jrand48(tmp_seed) >> 7) & 0xFF;
		memcpy(ul_jrand_seed, tmp_seed, sizeof(ul_jrand_seed) - sizeof(uint16_t));
	}
}

#endif





#if defined(TEST_PROGRAM) || defined(BUILD_MONOLITHIC)

#if defined(BUILD_MONOLITHIC)
#define main   uuid_test_randutils_main
#endif

int main(int argc, const char** argv)
{
	unsigned int v, i;

	/* generate and print 10 random numbers */
	for (i = 0; i < 10; i++) {
		random_get_bytes(&v, sizeof(v));
		printf("%d\n", v);
	}

	return EXIT_SUCCESS;
}

#endif /* TEST_PROGRAM */

