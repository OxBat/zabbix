/* libFuzzer harness: zbx_xml_to_json (XML-to-JSON preprocessing).
 *
 * Attacker-reachable via: the item VALUE returned by a monitored target when an
 * "XML to JSON" preprocessing step is configured (e.g. an HTTP agent item whose
 * endpoint returns XML). Runs on server / proxy preprocessing workers on fully
 * attacker-controlled data. Exercises the hand-rolled libxml2 tree-walk
 * (vector_to_json recursion, sibling array-grouping, attribute pairing).
 */
#include "zbxcommon.h"
#include "zbxxml.h"

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char	*xml, *jstr = NULL, *errmsg = NULL;

	/* NUL-terminated heap copy sized exactly to size+1 (tight, so ASan
	 * detects any read/write past the end); zbx_xml_to_json takes char* */
	xml = zbx_malloc(NULL, size + 1);
	memcpy(xml, data, size);
	xml[size] = '\0';

	if (SUCCEED == zbx_xml_to_json(xml, &jstr, &errmsg))
		zbx_free(jstr);

	zbx_free(errmsg);
	zbx_free(xml);

	return 0;
}
