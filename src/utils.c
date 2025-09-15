#include "ft_ssl.h"

inline u32 rotu32r(u32 value, u32 amount) {
  return (value >> amount) | (value << (32 - amount));
}

inline u32 rotu32l(u32 value, u32 amount) {
  return (value << amount) | (value >> (32 - amount));
}