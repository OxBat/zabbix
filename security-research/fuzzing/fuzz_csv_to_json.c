/* libFuzzer harness: item_preproc_csv_to_json (CSV-to-JSON preprocessing).
 *
 * Attacker-reachable via: the item VALUE returned by a monitored target when a
 * "CSV to JSON" preprocessing step is configured. Runs on server / proxy
 * preprocessing workers. Input data is fully attacker-controlled.
 *
 * The first byte selects a parameter configuration (delimiter / quote / header
 * flag); the remainder is the CSV payload.
 */
#include "zbxcommon.h"
#include "zbxvariant.h"

int	item_preproc_csv_to_json(zbx_variant_t *value, const char *params, char **errmsg);

static const char	*params_variants[] = {
	"\n\n0",		/* default ',' delimiter, no quote, no header      */
	"\n\n1",		/* default ',' delimiter, no quote, header line    */
	",\n\"\n1",		/* ',' delimiter, '"' quote, header line           */
	";\n'\n0",		/* ';' delimiter, '\'' quote, no header            */
	"\t\n\"\n1"		/* tab delimiter, '"' quote, header line           */
};
#define PARAMS_NUM	(sizeof(params_variants) / sizeof(params_variants[0]))

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	zbx_variant_t	value;
	char		*errmsg = NULL, *buf;
	const char	*params;

	if (0 == size)
		return 0;

	params = params_variants[data[0] % PARAMS_NUM];
	data++;
	size--;

	/* NUL-terminated heap copy sized exactly to strlen+1 (tight, so ASAN
	 * detects any read/write past the end) */
	buf = zbx_malloc(NULL, size + 1);
	memcpy(buf, data, size);
	buf[size] = '\0';

	zbx_variant_set_str(&value, buf);

	if (SUCCEED == item_preproc_csv_to_json(&value, params, &errmsg))
		zbx_variant_clear(&value);
	else
		zbx_variant_clear(&value);

	zbx_free(errmsg);

	return 0;
}
