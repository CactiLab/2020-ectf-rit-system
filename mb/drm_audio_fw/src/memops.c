
#include <stdint.h>

void* memset(void* buf, int c, size_t n) {
	uint8_t* b = buf;
	while (n) {
		b[n] = (uint8_t)c;
		--n;
	}
	return buf;
}

void* memcpy(void* dest, const void* src, size_t n) {
	uint8_t* s = src, * d = dest;
	if (n) { //deal with 0-length copy
		--n; 
		do {
			d[n] = s[n];
			--n;
		} while (n);
	}
	return dest;
}

void* memmove(void* dest, const void* src, size_t n) {
	uint8_t* s = src, * d = dest;
	if (n) {
		if (d > s) { //copy starting from the end of each array
			--n;
			do {
				d[n] = s[n];
				--n;
			} while (n);
		}
		else {
			for (size_t i = 0; i < n; ++i) //copy from beginning (end of d approx equal to start of s)
				d[i] = s[i];
		}
	}
	return dest;
}

/*
returns:
	+ if s1>s2
	0 if s1==s2
	- if s1<s2
*/
int memcmp(const void* s1, const void* s2, size_t n) {
	uint8_t* m1 = s1, * m2 = s2, c1, c2;
	for (size_t i = 0; i < n; ++i) {
		c1 = m1[i];
		c2 = m2[i];
		if (c1 > c2)
			return 1;
		else if (c2 > c1)
			return -1;
		//else c2==c1, continue
	}
	return 0;
}

void* copytolocal(void* fpga_dest, const void* arm_src, size_t n) {
#error define this function (xil_memcpy or something like that)
	return NULL;
}

void* copyfromlocal(void* arm_dest, const void* fpga_src, size_t n) {
#error define this function (xil_memcpy or something like that)
	return NULL;
}