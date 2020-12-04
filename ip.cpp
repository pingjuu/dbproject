#include "ip.h"
#include <cstdio>

Ip::Ip(const std::string r) {
	unsigned int a, b, c, d;
	int res = sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != SIZE) {
		fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip::operator std::string() const {
	char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(ip_ & 0xFF000000) >> 24,
		(ip_ & 0x00FF0000) << 16,
		(ip_ & 0x0000FF00) >> 8,
		(ip_ & 0x000000FF));
	return std::string(buf);
}

std::string ipp(uint32_t address){
    char buf[32]; // enough size
	sprintf(buf, "%u.%u.%u.%u",
		(address & 0x000000FF),
        (address & 0x0000FF00) >> 8,
        (address & 0x00FF0000) >> 16,
        (address & 0xFF000000) >> 24);
	return std::string(buf);
}