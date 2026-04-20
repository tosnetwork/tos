#define MAP_NAME               at_neigh4_hmap
#define MAP_ELE_T              at_neigh4_entry_t
#define MAP_KEY_T              uint
#define MAP_KEY                ip4_addr
#define MAP_KEY_HASH(key,seed) at_uint_hash( (*(key)) ^ ((uint)seed) )
#define MAP_ELE_MOVE(c,d,s)     do { \
                                  at_neigh4_entry_t * _src = (s); \
                                  at_neigh4_entry_atomic_st((d),_src); \
                                  _src->ip4_addr = 0U; \
                                } while(0)
