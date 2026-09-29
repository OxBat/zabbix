/* libFuzzer harness: item_preproc_snmp_walk_to_json (SNMP walk -> JSON / LLD).
 *
 * Attacker-reachable via: the item VALUE returned by a monitored SNMP target
 * when an "SNMP walk to JSON" preprocessing step is configured. Runs on
 * server / proxy preprocessing workers on fully attacker-controlled data.
 * Exercises the hand-rolled walk parser (preproc_snmp_parse_line ->
 * pair_parse_oid / parse_type / parse_value) and the hex/bits/mac value
 * conversions.
 *
 * First byte selects a param template (field mappings + format flag); the
 * remainder is the raw SNMP walk text (the attacker-controlled value).
 */
#include "zbxcommon.h"
#include "zbxvariant.h"

int	item_preproc_snmp_walk_to_json(zbx_variant_t *value, const char *params, char **errmsg);

static const char	*params_variants[] = {
	"f\n.1.3.6.1\n0",		/* plain, no conversion                    */
	"f\n.1.3.6.1\n1",		/* UTF8_FROM_HEX                           */
	"f\n.1.3.6.1\n2",		/* MAC_FROM_HEX                            */
	"a\n.1.3.6.1.2\n1\nb\n.1.3.6.1.4\n2",	/* two fields, hex + mac   */
	"f\n.1\n1"			/* short prefix, matches many OIDs         */
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

	buf = zbx_malloc(NULL, size + 1);
	memcpy(buf, data, size);
	buf[size] = '\0';

	zbx_variant_set_str(&value, buf);

	if (SUCCEED == item_preproc_snmp_walk_to_json(&value, params, &errmsg))
		zbx_variant_clear(&value);
	else
		zbx_variant_clear(&value);

	zbx_free(errmsg);

	return 0;
}
