#ifndef HEADER_at_util_at_yaml_h
#define HEADER_at_util_at_yaml_h

/* at_yaml.h - Minimal YAML parser for test vector files

   This is a simplified YAML parser designed specifically for parsing
   TCK (Test Compatibility Kit) test vector files. It supports:
   - Key-value pairs
   - Arrays of objects (list items starting with '- ')
   - String values (with or without quotes)
   - Integer values
   - Boolean values (true/false)

   Limitations:
   - No nested objects (except within array items)
   - No multi-line strings
   - No anchors or aliases
   - Max 64 fields per object
   - Max 1024 array items
*/

#include "at/crypto/at_crypto_base.h"

/* Maximum sizes - tuned for TCK test vector files
   Note: Large hex strings (2048+ chars) require AT_YAML_MAX_VALUE_LEN >= 4096
   WARNING: at_yaml_doc_t is ~40MB! Do NOT allocate on stack. Use static or heap. */
#define AT_YAML_MAX_KEY_LEN     (64)
#define AT_YAML_MAX_VALUE_LEN   (4096)
#define AT_YAML_MAX_FIELDS      (24)
#define AT_YAML_MAX_ITEMS       (32)
#define AT_YAML_MAX_ARRAYS      (12)
#define AT_YAML_MAX_LINE_LEN    (4160)

/* Value types */
#define AT_YAML_TYPE_STRING       (0)
#define AT_YAML_TYPE_INT          (1)
#define AT_YAML_TYPE_BOOL         (2)
#define AT_YAML_TYPE_INT_ARRAY    (3)  /* Integer array [1, 2, 3] or - 1\n- 2 */
#define AT_YAML_TYPE_STRING_ARRAY (4)  /* String array ['a', 'b'] or - 'a'\n- 'b' */

/* Maximum items in an array field */
#define AT_YAML_MAX_INT_ARRAY_ITEMS    (64)
#define AT_YAML_MAX_STRING_ARRAY_ITEMS (16)
#define AT_YAML_MAX_STRING_ITEM_LEN    (72)   /* 32-byte pubkey hex (64) + margin */

/* A single key-value field
   Size: ~5KB per field (dominated by value[4096] and int_array[512]) */
typedef struct {
  char key[ AT_YAML_MAX_KEY_LEN ];
  char value[ AT_YAML_MAX_VALUE_LEN ];
  int  type;  /* AT_YAML_TYPE_* */
  /* For AT_YAML_TYPE_INT_ARRAY: integer array support */
  long int_array[ AT_YAML_MAX_INT_ARRAY_ITEMS ];
  int  int_array_count;
  /* For AT_YAML_TYPE_STRING_ARRAY: string array support (for short strings like pubkey hex) */
  char str_array[ AT_YAML_MAX_STRING_ARRAY_ITEMS ][ AT_YAML_MAX_STRING_ITEM_LEN ];
  int  str_array_count;
} at_yaml_field_t;

/* An object (collection of fields) */
typedef struct {
  at_yaml_field_t fields[ AT_YAML_MAX_FIELDS ];
  int             field_count;
} at_yaml_obj_t;

/* An array of objects */
typedef struct {
  at_yaml_obj_t items[ AT_YAML_MAX_ITEMS ];
  int           item_count;
} at_yaml_array_t;

/* Root document with named arrays and top-level fields */
typedef struct {
  at_yaml_obj_t   root;           /* Top-level fields */
  char            array_names[ AT_YAML_MAX_ARRAYS ][ AT_YAML_MAX_KEY_LEN ];
  at_yaml_array_t arrays[ AT_YAML_MAX_ARRAYS ];
  int             array_count;
} at_yaml_doc_t;

AT_PROTOTYPES_BEGIN

/* Parse a YAML file into a document structure.
   Returns 0 on success, -1 on error. */
int
at_yaml_parse_file( at_yaml_doc_t * doc,
                    char const *    filename );

/* Parse a YAML string into a document structure.
   Returns 0 on success, -1 on error. */
int
at_yaml_parse_string( at_yaml_doc_t * doc,
                      char const *    yaml_str );

/* Get a top-level string field value.
   Returns the value or NULL if not found. */
char const *
at_yaml_get_string( at_yaml_doc_t const * doc,
                    char const *          key );

/* Get a top-level integer field value.
   Returns the value or default_val if not found. */
long
at_yaml_get_int( at_yaml_doc_t const * doc,
                 char const *          key,
                 long                  default_val );

/* Get a named array from the document.
   Returns the array or NULL if not found. */
at_yaml_array_t const *
at_yaml_get_array( at_yaml_doc_t const * doc,
                   char const *          name );

/* Get a string field from an object.
   Returns the value or NULL if not found. */
char const *
at_yaml_obj_get_string( at_yaml_obj_t const * obj,
                        char const *          key );

/* Get an integer field from an object.
   Returns the value or default_val if not found. */
long
at_yaml_obj_get_int( at_yaml_obj_t const * obj,
                     char const *          key,
                     long                  default_val );

/* Get a boolean field from an object.
   Returns 1 for true, 0 for false or if not found. */
int
at_yaml_obj_get_bool( at_yaml_obj_t const * obj,
                      char const *          key );

/* Get an integer array field from an object.
   Returns count of items (0 if not found or not array type).
   Items are copied to out[] up to max_items. */
int
at_yaml_obj_get_int_array( at_yaml_obj_t const * obj,
                           char const *          key,
                           long *                out,
                           int                   max_items );

/* Get a string array field from an object.
   Returns count of items (0 if not found or not array type).
   Caller provides array of char pointers which will be set to point
   directly into the field's storage (valid until doc is freed). */
int
at_yaml_obj_get_string_array( at_yaml_obj_t const * obj,
                              char const *          key,
                              char const **         out,
                              int                   max_items );

/* Convert a hex string to bytes.
   Returns number of bytes written, or -1 on error. */
int
at_yaml_hex_to_bytes( uchar *      out,
                      ulong        out_sz,
                      char const * hex );

AT_PROTOTYPES_END

#endif /* HEADER_at_util_at_yaml_h */
