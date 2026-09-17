/* recovered and derived=boolean_lut */
#include <stdint.h>

uint32_t and(uint32_t i0, uint32_t i1) {
  if (i0 == 0 && i1 == 0) return 0;
  if (i0 == 1 && i1 == 0) return 0;
  if (i0 == 0 && i1 == 1) return 0;
  if (i0 == 1 && i1 == 1) return 1;
  return 0;
}
