/* libFuzzer harness for Zabbix JSON parser (unauth trapper/agent/sender protocol). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zbxjson.h"

/* Recursively walk a parsed JSON structure to exercise decode paths. */
static void walk(const struct zbx_json_parse *jp, int depth)
{
	const char	*p = NULL;
	char		name[256];
	char		*value = NULL;
	size_t		value_alloc = 0;
	zbx_json_type_t	type;

	if (depth > 32)
		return;

	/* Try object iteration (name/value pairs). */
	while (NULL != (p = zbx_json_pair_next(jp, p, name, sizeof(name))))
	{
		struct zbx_json_parse	jp_child;

		if (SUCCEED == zbx_json_brackets_open(p, &jp_child))
			walk(&jp_child, depth + 1);

		zbx_json_decodevalue_dyn(p, &value, &value_alloc, &type);
	}

	/* Try array iteration (values). */
	p = NULL;
	while (NULL != (p = zbx_json_next(jp, p)))
	{
		struct zbx_json_parse	jp_child;

		if (SUCCEED == zbx_json_brackets_open(p, &jp_child))
			walk(&jp_child, depth + 1);

		zbx_json_next_value_dyn(jp, p, &value, &value_alloc, &type);
	}

	if (NULL != value)
		zbx_free(value);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char			*buf;
	struct zbx_json_parse	jp;

	buf = (char *)malloc(size + 1);
	if (NULL == buf)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	if (SUCCEED == zbx_json_open(buf, &jp))
		walk(&jp, 0);

	free(buf);
	return 0;
}
