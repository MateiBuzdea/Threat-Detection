#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAXLEN 1000
#define SIZE 1000
#define IP_MAXLEN 16

// some macros for usual time numers
#define DAY_SECONDS 86400
#define HOUR_SECONDS 3600
#define MINUTE_SECONDS 60

// some macros for field numbers
#define FLOW_DURATION_DAYS 4
#define FLOW_DURATION_HOURS 6
#define FLOW_DURATION_MINS 7
#define FLOW_DURATION_SECS 8
#define FLOW_PAYLOAD_AVG 20
#define SRC_IP 0
#define DST_IP 2

void split(char string[], char sep, char result[])
{
	// this function takes the string before a separator if existent
	char sep_arr[] = { sep, '\0'}, tmp[MAXLEN];
	strcpy(tmp, string);
	if (strchr(tmp, sep))
		strcpy(result, strtok(tmp, sep_arr));
	else
		strcpy(result, tmp);
}

void parse_url(char url[], char host[], char path[])
{
	char tmp_url[MAXLEN];

	// get rid of fragments if case
	split(url, '#', tmp_url);

	// get rid of protocol
	if (strstr(tmp_url, "://")) {
		// here we only take the part of the url after the protocol
		strcpy(url, strstr(tmp_url, "://") + 3);
	}

	// now get the host
	split(url, '/', host);
	strcpy(tmp_url, url + strlen(host));

	// now check if we have a path and get it
	split(tmp_url, '?', path);
}

int is_malicious(char host[], char path[], char **blacklist, int nr_hosts)
{
	// check if host is blacklisted
	int i = 0;
	for (i = 0; i < nr_hosts; i++) {
		if (strstr(host, blacklist[i]))
			return 1;
	}

	// check for long hostnames
	if (strlen(host) > 31)
		return 1;

	// check for bad file extensions
	if (strstr(path, ".exe") || strstr(path, ".bin") || strstr(path, ".sh"))
		return 1;

	// if connecting to a specific port or credentials, maybe malicious
	if (strstr(host, "@") || strstr(host, ":"))
		return 1;

	// check for bad chars
	if (strstr(path, "~") && !strstr(path, ".htm"))
		return 1;

	// if only numbers and dots may be a malicious ip
	int no_numbers = 0;
	for (i = 0; i < (int)strlen(host); i++)
		if (host[i] >= '0' && host[i] <= '9')
			no_numbers++;
	if (no_numbers >= (float)(0.1 * strlen(host)))
		return 1;

	// check if 'com' is present multiple times
	char *p = strstr(host, "com");
	if (p)
		if (strstr(p + 3, "com"))
			return 1;

	// check for some weird strings
	if (strstr(path, "secur") || strstr(path, "paypal") ||
		strstr(path, "wp-admin"))
		return 1;

	return 0;
}

int task1(void)
{
	// load the urls file and the blacklist domains_database
	FILE *urls_file = fopen("../data/url_dataset/urls.in", "r");
	FILE *blacklist_file = fopen("../data/url_dataset/domains_database", "r");
	FILE *predictions_file = fopen("urls-predictions.out", "w");

	int i = 0;
	char **blacklist = malloc(SIZE * sizeof(char *));
	if (!blacklist) {
		printf("Malloc error\n");
		exit(-1);
	}
	for (i = 0; i < SIZE; i++) {
		char *tmp_v = calloc(MAXLEN, sizeof(char));
		if (!tmp_v) {
			printf("Malloc error\n");
			exit(-1);
		}
		blacklist[i] = tmp_v;
	}

	// read the contents of the blacklist
	int nr_hosts = 0;
	while (1) {
		fscanf(blacklist_file, " %s", blacklist[nr_hosts++]);
		if (feof(blacklist_file))
			break;
	}
	fclose(blacklist_file);

	// now get each url and check if it is malicious
	char url[MAXLEN], host[MAXLEN], path[MAXLEN];
	while (1) {
		fscanf(urls_file, " %s", url);
		if (feof(urls_file))
			break;

		// parse the url
		parse_url(url, host, path);

		//check if malicious
		if (is_malicious(host, path, blacklist, nr_hosts)) {
			fprintf(predictions_file, "1\n");
			strcpy(blacklist[nr_hosts++], host);
		} else {
			fprintf(predictions_file, "0\n");
		}
	}

	// close everything
	fclose(predictions_file);
	fclose(urls_file);

	// and free memory
	for (i = 0; i < SIZE; i++)
		free(blacklist[i]);
	free(blacklist);

	return 0;
}

void parse_traffic(char packet[], double *duration, double *payload_avg,
				   char src_ip[], char dst_ip[])
{
	int field_no = 0;
	*duration = 0;

    // now split the packet into parts
	char *field = strtok(packet, ":, ");
	while (field) {
		switch (field_no) {
		case SRC_IP:
			strcpy(src_ip, field);
			break;

		case DST_IP:
			strcpy(dst_ip, field);
			break;

		case FLOW_DURATION_DAYS:
			*duration += DAY_SECONDS * atof(field);
			break;

		case FLOW_DURATION_HOURS:
			*duration += HOUR_SECONDS * atof(field);
			break;

		case FLOW_DURATION_MINS:
			*duration += MINUTE_SECONDS * atof(field);
			break;

		case FLOW_DURATION_SECS:
			*duration += atof(field);
			break;

		case FLOW_PAYLOAD_AVG:
			*payload_avg = atof(field);
			break;

		default:
			break;
		}

		field = strtok(NULL, ":, ");
		field_no++;
	}
}

int is_malicious_traffic(char packet[])
{
	double duration, payload_avg;
	char src_ip[IP_MAXLEN], dst_ip[IP_MAXLEN];

	parse_traffic(packet, &duration, &payload_avg, src_ip, dst_ip);

    // check if payload is 0
	if (payload_avg == 0)
		return 0;

    // if broadcast, probably not malicious
	if (!strcmp(dst_ip, "255.255.255.255"))
		return 0;

    // check for duration
	if (duration > 1.0)
		return 1;

    // check for known signs of cryptominer
	if (payload_avg == 40.0)
		return 1;

	return 0;
}

int task2(void)
{
    // load the urls file and the blacklist domains_database
	FILE *traffic_file = fopen("../data/network_dataset/traffic.in", "r");
	FILE *predictions_file = fopen("traffic-predictions.out", "w");

    // now get each packet and check if it is malicious
	char packet[SIZE];
	char ip[IP_MAXLEN];
	fgets(packet, 300, traffic_file);
	while (1) {
		fgets(packet, 200, traffic_file);
		if (feof(traffic_file))
			break;

		//check if malicious
		int res = is_malicious_traffic(packet);
		if (res)
			fprintf(predictions_file, "1\n");
		else
			fprintf(predictions_file, "0\n");
	}

    // close everything
	fclose(predictions_file);
	fclose(traffic_file);

	return 0;
}

int main(void)
{
	task1();
	task2();

	return 0;
}
