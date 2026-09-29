/* libFuzzer harness: LLD (low-level discovery) macro extraction + substitution.
 *
 * Attacker path: a monitored target returns discovery JSON for an LLD rule.
 * lld_extract_entries() turns it into {#MACRO}->value entries (BOTH the macro
 * names and values are attacker-controlled), then zbx_substitute_lld_macros()
 * splices those values into item/trigger/host prototype templates. Runs on the
 * Zabbix server. This harness fuzzes the discovery JSON and substitutes the
 * resulting macros into a range of template forms (plain, function, user and
 * expression macros), hunting OOB read-into-output (info leak), OOB write, or
 * crash in the token parser / splicer.
 */
#include "zbxcommon.h"
#include "zbxjson.h"
#include "zbxexpr.h"
#include "../../src/zabbix_server/lld/lld.h"

static const char	*templates[] = {
	"{#MACRO}",
	"prefix {#A} mid {#B} tail {#C}",
	"{{#MACRO}.regsub(\"(.*)\", \\1)}",
	"{{#MACRO}.fmtnum(2)}",
	"{{#A}.iregsub(\"([0-9]+)\", \\1)} {{#B}.tr(\"a-z\",\"A-Z\")}",
	"{$USERMACRO:\"{#MACRO}\"}",
	"{?{#A}+{#B}}",
	"\"{#MACRO}\" \\ {#A} \"{#B}\"",
	"{{#MACRO}.regsub(\"^(.{0,5})\", \\1)} {#MACRO} {#MACRO}",
	"a{#A}b{#B}c{#C}d{#MACRO}e{#A}f{#B}g"
};
#define TEMPLATES_NUM	(sizeof(templates) / sizeof(templates[0]))

/* escaping flags exercised on the (attacker-controlled) macro value */
static const int	escape_flags[] = {
	0,
	ZBX_TOKEN_JSON,
	ZBX_TOKEN_REGEXP,
	ZBX_TOKEN_REGEXP_OUTPUT,
	ZBX_TOKEN_XPATH,
	ZBX_TOKEN_PROMETHEUS,
	ZBX_TOKEN_JSONPATH,
	ZBX_TOKEN_STRING,
	ZBX_TOKEN_STR_REPLACE
};
#define ESCAPE_FLAGS_NUM	(sizeof(escape_flags) / sizeof(escape_flags[0]))

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char				*json, *error = NULL, errbuf[256];
	zbx_jsonobj_t			obj;
	zbx_hashset_t			entries;
	zbx_vector_lld_macro_path_ptr_t	macro_paths;
	int				flags;

	if (0 == size)
		return 0;

	/* first byte selects an escaping variant so the escape transforms */
	/* (zbx_json_escape / regexp_escape / xml_escape_xpath / ...) run   */
	/* on the attacker-controlled macro value */
	flags = ZBX_MACRO_FUNC | escape_flags[data[0] % ESCAPE_FLAGS_NUM];
	data++;
	size--;

	json = zbx_malloc(NULL, size + 1);
	memcpy(json, data, size);
	json[size] = '\0';

	if (SUCCEED != zbx_jsonobj_open(json, &obj))
	{
		zbx_free(json);
		return 0;
	}

	zbx_vector_lld_macro_path_ptr_create(&macro_paths);
	zbx_hashset_create(&entries, 16, lld_entry_hash, lld_entry_compare);

	if (SUCCEED == lld_extract_entries(&entries, NULL, &obj, &macro_paths, &error))
	{
		zbx_hashset_iter_t	iter;
		zbx_lld_entry_t		*entry;

		zbx_hashset_iter_reset(&entries, &iter);
		while (NULL != (entry = (zbx_lld_entry_t *)zbx_hashset_iter_next(&iter)))
		{
			for (size_t i = 0; i < TEMPLATES_NUM; i++)
			{
				char	*buf = zbx_strdup(NULL, templates[i]);

				*errbuf = '\0';
				zbx_substitute_lld_macros(&buf, entry, flags, errbuf, sizeof(errbuf));
				zbx_free(buf);
			}
		}
	}

	zbx_free(error);
	{
		zbx_hashset_iter_t	it;
		zbx_lld_entry_t		*e;

		zbx_hashset_iter_reset(&entries, &it);
		while (NULL != (e = (zbx_lld_entry_t *)zbx_hashset_iter_next(&it)))
			lld_entry_clear(e);
	}
	zbx_hashset_destroy(&entries);
	zbx_vector_lld_macro_path_ptr_destroy(&macro_paths);
	zbx_jsonobj_clear(&obj);
	zbx_free(json);

	return 0;
}
