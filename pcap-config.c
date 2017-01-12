#include <pcap.h>
#include <pcap-int.h>

#include "pcap-config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>


extern char **environ;


struct pcap_conf_key pcap_conf_keys[] =
{
	PCAP_CONF_KEY(def_group),
	PCAP_CONF_KEY(caplen),
	PCAP_CONF_KEY(rx_slots),
	PCAP_CONF_KEY(tx_slots),
	PCAP_CONF_KEY(tx_sync),
	PCAP_CONF_KEY(tx_hw_queue),
	PCAP_CONF_KEY(tx_idx_thread),
	PCAP_CONF_KEY(vlan),
	PCAP_CONF_KEY(lang)
};


void
pcap_group_map_dump(struct pcap_group_map *map)
{
	int n = 0;
	for(; n < map->size; n++)
		fprintf(stderr, "pcap-config: config group for dev '%s' = %d\n", map->entry[n].dev, map->entry[n].group);
}


void
pcap_group_map_free(struct pcap_group_map *map)
{
	int n = 0;
	for(; n < map->size; n++)
		free(map->entry[n].dev);
}


int
pcap_group_map_set(struct pcap_group_map *map, const char *dev, int group)
{
	int n = 0;
	for(; n < map->size; n++) {
		if (strcmp(map->entry[n].dev, dev) == 0)
			break;
	}

	if (n == PCAP_FANOUT_GROUP_MAP_SIZE)
		return -1;

	free(map->entry[n].dev);
	map->entry[n].dev = strdup(dev);
	map->entry[n].group = group;

	if (n == map->size)
		map->size++;

	return 0;
}


int
pcap_group_map_get(struct pcap_group_map const *map, const char *dev)
{
	int n = 0;
	for(; n < map->size; n++) {
		if (strcmp(map->entry[n].dev, dev) == 0)
			return map->entry[n].group;
	}
	return -1;
}


static void
pcap_warn_if(int index, const char *filename, const char *key)
{
	if (index != PCAP_FANOUT_GROUP_DEF)
		fprintf(stderr, "pcap-config:%s: key %s: group ignored!\n", filename, key);
}


int
pcap_parse_integers(int *out, size_t max, const char *in)
{
	size_t n = 0; int ret = 0;

	int store_int(const char *num) {
		if (n < max) {
			out[n++] = atoi(num);
			ret++;
		}
		return 0;
	}

	if (pcap_string_for_each_token(in, ",", store_int) < 0)
		return -1;
	return ret;
}


int
pcap_string_for_each_token(const char *ds, const char *sep, pcap_string_handler_t handler)
{
        char * mutable = strdup(ds);
        char *str, *token, *saveptr;
        int i, ret = 0;

        for (i = 1, str = mutable; ; i++, str = NULL)
        {
                token = strtok_r(str, sep, &saveptr);
                if (token == NULL)
                        break;
                if (handler(token) < 0) {
		        ret = PCAP_ERROR;
			break;
		}
        }

        free(mutable);
	return ret;
}


char *
pcap_string_first_token(const char *str, const char *sep)
{
	char *end;

	if ((end = strstr(str, sep))) {
		char *ret = malloc(end - str + 1);
		strncpy(ret, str, end - str);
		ret[end - str] = '\0';
		return ret;
	}

	return strdup(str);
}


char *
pcap_string_trim(char *str)
{
	int i = 0, j = strlen(str) - 1;

	while (isspace(str[i]) && str[i] != '\0')
		i++;
	while (j >= 0 && isspace(str[j]))
		j--;

	str[j+1] = '\0';
	return str+i;
}


char *
pcap_string_append(char *str1, const char *str2)
{
	char *ret;
	if (str1) {
		ret = realloc(str1, strlen(str1) + strlen(str2) + 1);
		strcat(ret, str2);
	}
	else {
		ret = malloc(strlen(str2) + 1);
		strcpy(ret, str2);
	}
	return ret;
}


static const char *
pcap_conf_get_key_name(char const *key)
{
	static __thread char storage[64];
	char * p = strchr(key, '@');
	int len;
	if (p == NULL)
		return key;

	len =  min(63, p - key);
	strncpy(storage, key, len);
	storage[len] = '\0';
	return storage;
}

static int
pcap_conf_get_key_index(char const *key)
{
	char * p = strchr(key, '@');
	if (p == NULL)
		return -1;
	return atoi(p+1);
}

static int
pcap_conf_find_key(const char *key, int *index)
{
	char const *this_key;
        int n;

	this_key = pcap_conf_get_key_name(key);
        *index = pcap_conf_get_key_index(key);

	for(n = 0; n < PCAP_CONF_KEY_EOF; n++)
	{
		if (strcasecmp(pcap_conf_keys[n].value, this_key) == 0)
			return n;
	}
	return -1;
}


char *
pcap_getenv_name(char *var)
{
	static __thread char name[64];
	char * end = strchr(var, '=');
	if (end) {
		strncpy(name, var, (size_t)min(63,end-var));
		name[min(63,end-var)] = '\0';
	}
	else {
		strcpy(name, var);
	}
	return name;
}

char *
pcap_getenv_value(char *var)
{
	char *eq = strchr(var, '=');
	return eq ? eq+1 : NULL;
}


char **
pcap_getenv(char *name)
{
	static __thread char *env[64];
        char **cur = environ;
	int size = 0;

	while (*cur && size < 64) {
		if (strncmp(*cur, name, strlen(name)) == 0) {
			env[size++] = *cur;
		}
		cur++;
	}
	env[size] = NULL;
	return env;
}



int
pcap_parse_config(struct pcap_fanout *opt, const char *filename)
{
	char line[1024];
	FILE *file;
	int rc = 0, n;

	file = fopen(filename, "r");
	if (!file) {
		fprintf(stderr, "pcap-config: could not open '%s' file!\n", filename);
		rc = -1; goto err;
	}

	for(n = 0; fgets(line, sizeof(line), file); n++) {

		char *key = NULL, *value = NULL, *tkey;
		int ktype, index, ret;

		ret = sscanf(line, "%m[^=]=%m[^\n]",&key, &value);
		if (ret < 0) {
			fprintf(stderr, "libcap:%s: parse error at: %s\n", filename, key);
			rc = -1; goto next;
		}

		if (ret == 0)
			goto next;

		/* ret > 0 */

		tkey = pcap_string_trim(key);
		if (strlen(tkey) == 0)
			continue;

		/*  strlen > 0 */

		if (line[0] == '>') {
			opt->lang_lit = pcap_string_append(opt->lang_lit, line+1);
			opt->lang_lit = pcap_string_append(opt->lang_lit, "\n");
			continue;
		}

		if (tkey[0] == '#') /* skip comments */
			continue;

		if (strncasecmp(tkey, "group_", 6) == 0)
		{
			char *dev = strdup(pcap_getenv_name(tkey + sizeof("group_")-1));
			if (pcap_group_map_set(&opt->group_map, dev, atoi(value)) < 0) {
				fprintf(stderr, "pcap-config:%s: '%s': group map error!\n", filename, tkey);
				rc = -1;
				goto next;
			}
			continue;
		}

		ktype = pcap_conf_find_key(tkey, &index);

		index = index == -1 ?  PCAP_FANOUT_GROUP_DEF : index;

		switch(ktype)
		{
			case PCAP_CONF_KEY_def_group:   pcap_warn_if(index, filename, tkey); opt->def_group = atoi(value);  break;
			case PCAP_CONF_KEY_caplen:	pcap_warn_if(index, filename, tkey); opt->caplen    = atoi(value);  break;
			case PCAP_CONF_KEY_rx_slots:	pcap_warn_if(index, filename, tkey); opt->rx_slots  = atoi(value);  break;
			case PCAP_CONF_KEY_tx_slots:	pcap_warn_if(index, filename, tkey); opt->tx_slots  = atoi(value);  break;
			case PCAP_CONF_KEY_tx_sync:	pcap_warn_if(index, filename, tkey); opt->tx_sync   = atoi(value);  break;
			case PCAP_CONF_KEY_tx_hw_queue:  {
				pcap_warn_if(index, filename, tkey);
				if (pcap_parse_integers(opt->tx_hw_queue, 4, value) < 0) {
					fprintf(stderr, "pcap-config:%s: parse error at: %s\n", filename, tkey);
					rc = -1;
				}
			} break;
			case PCAP_CONF_KEY_tx_idx_thread: {
				pcap_warn_if(index, filename, tkey);
				if (pcap_parse_integers(opt->tx_idx_thread, 4, value) < 0) {
					fprintf(stderr, "pcap-config:%s: parse error at: %s\n", filename, tkey);
					rc = -1;
				}
			} break;
			case PCAP_CONF_KEY_vlan: free (opt->vlan[index]); opt->vlan[index] = strdup(pcap_string_trim(value)); break;
			case PCAP_CONF_KEY_lang: free (opt->lang_src[index]); opt->lang_src[index] = strdup(pcap_string_trim(value)); break;
			case PCAP_CONF_KEY_error:
			default: {
				fprintf(stderr, "pcap-config:%s: parse error at: %s (invalid keyword)\n", filename, tkey);
				rc = -1;
			} break;
		}
	next:
		free(key);
		free(value);
		if (rc == -1)
			break;
	}

	fclose(file);

err:
	return rc;
}


