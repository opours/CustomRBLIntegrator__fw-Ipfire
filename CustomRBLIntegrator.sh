#!/bin/bash
#
##########################################################################################################
##													##
##					CustomRBLIntegrator						##
##													##
## Autor	: Mickaël DUBARD (www.opours.net)							##
## Version	: 0.1											##
## Created on	: 22.05.2024										##
## Last update	: 18.06.2024										##
## Description	:											##
##		 Add the possibility of including Iptables rules for custom real-time blackhole lists	##
##		 (RBLs) stored locally or imported via API, http or https. This script automate the  	##
##		 process of downloading, updating, and enforcing network security policies based on	##
##		 RBLs and other IP blacklist sources.							##
##		 Its primary function is to ensure that the firewall rules are continually updated   	##
##      	 to reflect the latest security intelligence, thereby protecting the network from	##
##		 potentia threats identified by various blacklist providers.				##
##													##
## License	: GPL v3										##
##		 This script is provided as is by its author, WITHOUT ANY WARRANTY. 			##
##		 It is free to use, modify, and redistribute as long as you mention the original and 	##
##		 adhere to the terms of the GPL v3 license. For more details on this license, 		##
##		 please visit: https://www.gnu.org/licenses/gpl-3.0.en.html 				##
##													##
##													##
##########################################################################################################
#
# Determines the script path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
#
# Configuration file path
CONFIG_FILE="$SCRIPT_DIR/CustomRBLIntegrator.conf"
#
# Load script configuration file
if ! source "$CONFIG_FILE"
	then
		echo "[ERROR]: Configuration file [$CONFIG_FILE] could not be loaded." >&2
		exit 1
fi
#
# Initialize the error tracking
error_occurred=false
#
# Help function to display usage
usage() {
	echo "Usage: $0 [-c] [-u] [-i] [-h]"
	echo "  -c  Check for the presence of the customized ipset list. If the list does not exist, the -i option will be automatically applied" 
	echo "  -u  Update RBL list only"
	echo "  -i  Implement IPs and subnetworks according to the existing referent list"
	echo "  -h  Display this help message"
	exit 1
}
#
# Initialize flags
check_presence_custom_RBL=false
update_only=false
implement_ips=false
error_occurred=false
valid_option=false
email_to_send=false
attempt_update=0
#
# Process command-line options
while getopts "cuih" opt; do
	case $opt in
		c) check_presence_custom_RBL=true ; valid_option=true ;;
		u) update_only=true ; valid_option=true ;;
		i) implement_ips=true; valid_option=true ;;
		h) usage ;;
		\?) usage ;;
	esac
done
#
# Exit if no valid option is provided
if ! $valid_option
	then
		echo "[ERROR] : No valid options provided !"
		usage
fi
#
#
#
#
#
# -----------------
# Useful functions
# -----------------
#
# Log actions to a file
log_action() {
	echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${LOG_FILE}"
}
#
# Log errors to a file and set error flag
log_error() {
	echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "${LOG_FILE}"
	error_occurred=true
}
#
# Fonction pour supprimer le fichier PID
cleanup() {
	rm -f "${PIDFILE}"
}
#
# Function to send email
send_mail() {
	if [ -n "$ADMIN_MAIL" ]
		then
			if $error_occurred
				then
					subject="[ERROR] RBL Integration Issues on $(hostname)"
					body="Errors occurred during the script execution on $(date). Please check the logs for details."
				else
					subject="An update has been performed by the CustomRBLIntegrator script on $(hostname)"
					body="CustomRBLIntegrator script has updated the RBL lists or/and Iptables rules on $(date). Please check the logs for details."
			fi
			log_action "> Send email notification to ADMIN_MAIL [ $ADMIN_MAIL ]"
			echo "Subject: $subject" > "${TMPMAILFILE}"
			echo "$body" >> "${TMPMAILFILE}"
			cat "${LOG_FILE}" >> "${TMPMAILFILE}"
			/usr/sbin/sendmail "$ADMIN_MAIL" < "${TMPMAILFILE}"
			[ -f "${TMPMAILFILE}" ] && rm "${TMPMAILFILE}"
		else
			log_action "> [INFO] ADMIN_MAIL variable is not set. Skipping email notification."
	fi
}
#
# Function to count ips and subnets
count_ips_and_subnets() {
	local file=$1
	local count_ips_v4=$(grep -oP '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$file" | wc -l)
	local count_subnets_v4=$(grep -oP '^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[1-2][0-9]|3[0-2])$' "$file" | wc -l)
	local count_ips_v6=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}:?|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$' "$file" | wc -l)
	local count_subnets_v6=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}:?|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$' "$file" | wc -l)
	echo "IPv4 Addresses: $count_ips_v4, IPv4 Subnets: $count_subnets_v4 || IPv6 Addresses: $count_ips_v6, IPv6 Subnets: $count_subnets_v6"
}
#
# Function for checking the validity of an IPv4 address
is_valid_ipv4() {
	local ip=$1
	IFS='.' read -r -a octets <<< "$ip"
	for octet in "${octets[@]}"
		do
			if ! [[ "$octet" =~ ^[0-9]+$ ]] || (( octet < 0 || octet > 255 ))
				then
					return 1
			fi
	done
	return 0
}
#
# Function for checking the validity of an IPv4 subnetwork
is_valid_ipv4_subnet() {
	local subnet=$1
	local ip="${subnet%/*}"
	local mask="${subnet#*/}"
	if is_valid_ipv4 "$ip" && (( mask >= 1 && mask <= 32 ))
		then
			return 0
		else
			return 1
	fi
}
#
# Function for checking the validity of an IPv6 address
is_valid_ipv6() {
	local ip=$1
	if [[ "$ip" =~ $valid_ipv6_regex ]]
		then
			return 0
		else
			return 1
	fi
}
#
# Function for checking the validity of an IPv6 subnetwork
is_valid_ipv6_subnet() {
	local subnet=$1
	local ip="${subnet%/*}"
	local mask="${subnet#*/}"
	if is_valid_ipv6 "$ip" && (( mask >= 0 && mask <= 128 ))
		then
			return 0
		else
			return 1
	fi
}
#
# Function for filtering and saving erroneous subnets
filter_erroneous_ips_subnets() {
	local file=$1
	local rbl_name=$2
	local VALID_IPV4_FILE=$3
	local ERRONEOUS_IPV4_FILE=$4
	local VALID_IPV6_FILE=$5
	local ERRONEOUS_IPV6_FILE=$6
	erroneous_count=0
	#
	: > "${TEMP_RBL_DIR}/ips-or-subnets_discarded.tmp"
	#
	# Count the total number of lines to be processed (IP addresses or subnets only)
	total_lines=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?' "$file" | wc -l)
	current_line=0
	#
	# Create a temporary file for erroneous lines
	local temp_erroneous_file=$(mktemp)
	#
	# Extract and verify IPv4 addresses and IPv4 and IPv6 subnets
	echo "   > Processing to create a single global personalised list of all customised RBLs loaded: total entries found for RBL [ $rbl_name ]: [ $total_lines ]..." >&2
	log_action "     > Processing to create a single global personalised list of all customised RBLs loaded: total entries found for RBL [ $rbl_name ]: [ $total_lines ]..." 
	log_action "       > Extract and verify IPv4/IPv6 addresses and subnets..."
	#
	# Extract and verify IPv4 addresses and IPv4 and IPv6 subnets
	grep -vP '^(#|$)' "${file}" | while read -r line
		do
			((current_line++))
			printf "\r\033[K     > Processing - Extract and verify IPv4/IPv6 addresses and subnets for custom RBL [ %s ]: (%d/%d)" "$rbl_name" "$current_line" "$total_lines" >&2
			# Force immediate display
			echo -n "" >&2
			#
			#
			if [[ "$line" =~ $valid_ipv6_subnet_regex ]]
				then
					if is_valid_ipv6_subnet "$line"
						then
							echo "$line $rbl_name" >> "${VALID_IPV6_FILE}"
						else
							echo "[SYNTAX ERROR IPV4 subnet] $line $rbl_name" >> "${ERRONEOUS_IPV6_FILE}"
					fi
				elif [[ "$line" =~ $valid_ipv6_regex ]]
					then
						if is_valid_ipv6 "$line"
							then
								echo "$line $rbl_name" >> "${VALID_IPV6_FILE}"
							else
								echo "[SYNTAX ERROR IPV6 IP] $line $rbl_name" >> "${ERRONEOUS_IPV6_FILE}"
						fi
				elif [[ "$line" =~ $valid_ipv4_subnet_regex ]]
					then
						if is_valid_ipv4_subnet "$line"
							then
								echo "$line $rbl_name" >> "${VALID_IPV4_FILE}"
							else
								echo "[SYNTAX ERROR IPV4 subnet] $line $rbl_name" >> "${ERRONEOUS_IPV4_FILE}"
						fi
				elif [[ "$line" =~ $valid_ipv4_regex ]]
						then
							if is_valid_ipv4 "$line" && ! [[ "$line" =~ $ipv4_without_mask_regex ]]
								then
									echo "$line $rbl_name" >> "${VALID_IPV4_FILE}"
								else
									echo "[SYNTAX ERROR IPV4 IP] $line $rbl_name" >> "${ERRONEOUS_IPV4_FILE}"
							fi
				else
					# If it is neither a valid IPv4 address nor a valid IPv6 address, we add it to the erroneous ones
					echo "[UNSPECIFIED SYNTAX ERROR] $line $rbl_name" >> "${temp_erroneous_file}"
			fi
	done
	#
	echo "" >&2 # Add a new line after the final printf display in the console
	echo "----------" >&2
	echo "" >&2
	echo "" >&2
	# Merge erroneous files
	log_action "     > Merge erroneous files ..."
	cat "${ERRONEOUS_IPV4_FILE}" "${ERRONEOUS_IPV6_FILE}" "${temp_erroneous_file}" >> "${REPORTS_DIR}/ips-or-subnets_discarded.error"
	#
	# Count erroneous lines if files exist, otherwise set to zero
	if [ -f "${REPORTS_DIR}/ips-or-subnets_discarded.error" ]
		then
			# Compter les lignes erronées pour ce fichier spécifique
			erroneous_count=$(wc -l < "$temp_erroneous_file")
			#
		else
			erroneous_count=0
	fi
	#
	# Clean up temporary file
	[ -f "${temp_erroneous_file}" ] && rm "${temp_erroneous_file}"
	#
	echo "$erroneous_count"
}
#
# Update the RBL list in the reference file
update_rbl_list() {
	#
	# Clear temporary file for new data
	: > "${TMP_FILE}"
	: > "${TMP_FILE_WITH_RBLS}"
	if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
		then
			: > "${GLOBAL_INFO_FILE}"
	fi
	#
	# Initialise output files
	: > "${ERRONEOUS_IPV4_FILE}"
	: > "${VALID_IPV4_FILE}"
	: > "${ERRONEOUS_IPV6_FILE}"
	: > "${VALID_IPV6_FILE}"
	: > "${REPORTS_DIR}/ips-or-subnets_discarded.error"
	#
	# Regular expressions for validating IPv4 addresses and subnets
	valid_ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
	valid_ipv4_subnet_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[1-2][0-9]|3[0-2])$'
	ipv4_without_mask_regex='^([0-9]{1,3}\.){3}0$'
	#
	# Regular expressions for validating IPv6 addresses and subnets
	valid_ipv6_regex='^(([0-9a-fA-F]{1,4}:){1,7}:?|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$'
	valid_ipv6_subnet_regex='^(([0-9a-fA-F]{1,4}:){1,7}:?|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$'
	#
	# Declaration of associative tables
	declare -A ipv4_valid_set
	declare -A ipv4_erroneous_set
	declare -A ipv6_valid_set
	declare -A ipv6_erroneous_set
	declare -A ip_counts
	declare -A network_counts
	#
	declare -a valid_rbls
	#
	local error_in_download=false
	#
	# Downloading and processing RBLs
	echo ""
	echo "> Downloading and processing custom RBLs..."
	log_action ""
	log_action "   > Update the RBL list in the reference file..."
	for url_info in "${STANDARD_URLS[@]}" "${LOCAL_RBL_FILES[@]}"
		do
			IFS=' ' read -r url name <<< "$url_info"
			temp_file="$TEMP_RBL_DIR/${name// /_}.txt"
			#
			if [[ "$url" =~ ^https?:// ]]
				then
					log_action "     > __For Standard URLs:__ Downloading and processing URL [ $url ] from name [ $name ]"
					# It's a URL, use curl to download
					rbl_data=$(curl -s "$url" | grep -vP '^(#|$)')
					rbl_type="standard URL"
				else
					log_action "     > __For Local RBL Files:__ Downloading and processing file [ $url ] from name [ $name ]"
					# It's a local file, use cat to read
					rbl_data=$(cat "$url" | grep -vP '^(#|$)')
					rbl_type="local file"
			fi
			#
			if [[ -n "$rbl_data" ]]
				then
					echo "$rbl_data" > "$temp_file"
					#
					# Filter only IP addresses and subnets
					grep -vP '^(#|$)' "$temp_file" > "${temp_file}.filtered"
					#
					# Log erroneous subnets
					log_action "       - Log erroneous IPs and/or subnets in [ $name ] RBL..."
					erroneous_count=$(filter_erroneous_ips_subnets "${temp_file}.filtered" "$name" "${VALID_IPV4_FILE}" "${ERRONEOUS_IPV4_FILE}" "${VALID_IPV6_FILE}" "${ERRONEOUS_IPV6_FILE}")
					log_action "         - Found [ $erroneous_count ] erroneous IPs and/or subnets in [ $name ] RBL"
					#
					# Count the number of occurrences in the resulting file for IPs and subnets
					ip_counts[$name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}(?=\s|$)' "${temp_file}.filtered" | wc -l)
					network_counts[$name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}/([1-9]|[1-2][0-9]|3[0-2])(?=\s|$)' "${temp_file}.filtered" | wc -l)
					ipv6_counts[$name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$' "${temp_file}.filtered" | wc -l)
					ipv6_network_counts[$name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$' "${temp_file}.filtered" | wc -l)
					#
					valid_rbls+=("$name")
					log_action "       - Success: Processed for [ $name ] with ${ip_counts[$name]} IPv4 IPs, ${network_counts[$name]} IPv4 networks, ${ipv6_counts[$name]} IPv6 IPs, and ${ipv6_network_counts[$name]} IPv6 networks"
					#
				else
					log_action "       - [WARNING] Failed to download or process $url from [ $name ]"
					error_in_download=true
					continue
			fi
			log_action ""
			log_action "----------"
	done
	#
	# Handling API URLs separately
	for api_info in "${API_URLS[@]}"
		do
			IFS='|' read -r url args name <<< "$api_info"
			log_action "     > __For API URLs:__ Downloading and processing URL [ $url ] from name [ $name ] with args [ $args ]"
			temp_file="$TEMP_RBL_DIR/${name// /_}.txt"
			#
			# Split args into an array
			read -r -a curl_args <<< "$args"
			#
			# Combine URL and args for curl command
			curl_command="curl -s -G ${curl_args[*]} \"$url\" -o \"$temp_file\""
			#
			# Log the command for debugging purposes
			log_action "       - Run command [ $curl_command ]"
			#
			# Execute the command
			eval $curl_command
			#
			if [[ -s "$temp_file" ]]
				then
					rbl_data=$(cat "$temp_file")
					#
					# Filter only IP addresses and subnets
					grep -vP '^(#|$)' "$temp_file" > "${temp_file}.filtered"
					#
					# Log erroneous subnets
					log_action "       - Log erroneous IPs and/or subnets in [ $name ] RBL..."
					erroneous_count=$(filter_erroneous_ips_subnets "${temp_file}.filtered" "$name" "${VALID_IPV4_FILE}" "${ERRONEOUS_IPV4_FILE}" "${VALID_IPV6_FILE}" "${ERRONEOUS_IPV6_FILE}")
					log_action "         - Found [ $erroneous_count ] erroneous subnets in [ $name ] RBL"
					#
					# Count the number of occurrences in the resulting file for IPs and subnets
					ip_counts[$name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}(?=\s|$)' "${temp_file}.filtered" | wc -l)
					network_counts[$name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}/([1-9]|[1-2][0-9]|3[0-2])(?=\s|$)' "${temp_file}.filtered" | wc -l)
					ipv6_counts[$name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$' "${temp_file}.filtered" | wc -l)
					ipv6_network_counts[$name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$' "${temp_file}.filtered" | wc -l)
					#
					valid_rbls+=("$name")
					log_action "       - Success: Processed for [ $name ] with ${ip_counts[$name]} IPv4 IPs, ${network_counts[$name]} IPv4 networks, ${ipv6_counts[$name]} IPv6 IPs, and ${ipv6_network_counts[$name]} IPv6 networks"
					#
				else
					log_action "       - [WARNING] Failed to download or process $url from [ $name ]"
					error_in_download=true
					continue
			fi
			log_action ""
			log_action "----------"
	done
	#
	if [ ${#valid_rbls[@]} -eq 0 ]
		then
			log_action "     > [ABORTING] No valid RBLs processed successfully!"
			trap cleanup EXIT
			exit 1 # Return with error
	fi
	#
	#
	# Merge the IPV4 and IPV6 lists into a single custom RBL list, keeping only the IPs and subnets without the RBL name 
	#
	# Initialise a temporary file for the merged list ${SORTED_NEW_IPS}
	merged_rbl_valid_file="${SORTED_NEW_IPS}"
	# Initialise output files
	: > "${merged_rbl_valid_file}"
	# Concatenate valid IPv4 and IPv6 files in a temporary file with RBL names
	cat "${VALID_IPV4_FILE}" "${VALID_IPV6_FILE}" > "${TEMP_RBL_DIR}/merged_rbl_valid_file.tmp"
	#
	# Find and save duplicates in a separate file, keeping the RBL names.
	awk '
	{
		ip = $1;
		rbl = ($2 ? $2 : "UNKNOWN");
		if (ip in ips) {
			if (index(ips[ip], rbl) == 0) {
				ips[ip] = ips[ip] "," rbl;
				count[ip]++;
			}
		} else {
			ips[ip] = rbl;
			count[ip] = 1;
		}
	}
	END {
		for (ip in ips) {
			if (count[ip] > 1) {
				print ip, ips[ip];
			}
		}
	}' "${TEMP_RBL_DIR}/merged_rbl_valid_file.tmp" > "${REPORTS_DIR}/duplicate_custom_rbl.txt"
	#
	# Create the final file without duplicates (using: awk ‘!seen[$1]++’) and only IP addresses and subnets (using: awk ‘{print $1}’).
	awk '{print $1}' "${TEMP_RBL_DIR}/merged_rbl_valid_file.tmp" | awk '!seen[$0]++' > "$merged_rbl_valid_file"
	#
	# Delete the temporary intermediate file
	[ -f "${TEMP_RBL_DIR}/merged_rbl_valid_file.tmp" ] && rm "${TEMP_RBL_DIR}/merged_rbl_valid_file.tmp"
	#
	#
	# Concatenate IPv4 and IPv6 error files in the same file
	cat "${ERRONEOUS_IPV4_FILE}" "${ERRONEOUS_IPV6_FILE}" > "${TEMP_RBL_DIR}/merged_custom-rbl_erroneous.tmp"
	#
	# Find and save duplicates in a separate file, keeping the RBL names.
	awk '
	{
		ip = $1;
		rbl = ($2 ? $2 : "UNKNOWN");
		if (ip in ips) {
			if (index(ips[ip], rbl) == 0) {
				ips[ip] = ips[ip] "," rbl;
				count[ip]++;
			}
		} else {
			ips[ip] = rbl;
			count[ip] = 1;
		}
	}
	END {
		for (ip in ips) {
			if (count[ip] > 1) {
				print ip, ips[ip];
			}
		}
	}' "${TEMP_RBL_DIR}/merged_custom-rbl_erroneous.tmp" > "${REPORTS_DIR}/merged_custom-rbl_erroneous.txt" 
	#
	# Delete the temporary intermediate file for incorrect IP addresses or subnets
	[ -f "${TEMP_RBL_DIR}/merged_custom-rbl_erroneous.tmp" ] && rm "${TEMP_RBL_DIR}/merged_custom-rbl_erroneous.tmp"
	#
	# Global summary file generation
	if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
		then
			echo "Global RBL Information" > "${GLOBAL_INFO_FILE}"
			echo "----------------------" >> "${GLOBAL_INFO_FILE}"
	fi
	#
	rbl_custom_merged_count=$(cat "${REPORTS_DIR}/merged_custom-rbl_erroneous.txt" 2>/dev/null | wc -l)
	#
	if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
		then
			echo "" >> "${GLOBAL_INFO_FILE}"
			echo "Erroneous IPs and subnets count for custom RBLs [ $rbl_custom_merged_count ]" >> "${GLOBAL_INFO_FILE}"
	fi
	# Retrieving the names of active Ipblocklist sets
	echo ""
	active_ipblocklist_sets=($(ipset list 2>/dev/null | grep '^Name:' | cut -d' ' -f2- | grep -v -E "^($IPV4_IPSET_NAME|$IPV6_IPSET_NAME)$"))
	#
	# Calculation of the total number of lines for active Ipblocklist sets
	log_action "     > Calculation of the total number of lines for active Ipblocklist sets"
	total_active_lines=0
	for rbl_name in "${active_ipblocklist_sets[@]}"; do
	file="$IPBLOCKLIST_CONF_DIR/$rbl_name.conf"
	if [ -f "$file" ]; then
		# Créer un fichier temporaire pour stocker les résultats du grep
		temp_file=$(mktemp)
		grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?' "$file" > "$temp_file"
		#
		active_lines=$(wc -l < "$temp_file")
		total_active_lines=$((total_active_lines + active_lines))
		initial_counts=$(count_ips_and_subnets "$temp_file")
		log_action "       - RBL name [ $rbl_name ]:  $initial_counts"
		#
		# Supprimer le fichier temporaire
		rm -f "$temp_file"
	fi
	log_action ""
	log_action "----------"
	done	
	#
	log_action "        - Total IPs and networks for all Ipblocklist sets (it is possible here for ips or subnetworks to be duplicated) : [ $total_active_lines ]"
	#
	##########################################################################################
	#
	# Ipfire Ipblocklist file verification
	#
	##########################################################################################
	#
	# Loading and checking for duplicates ONLY in active Ipblocklist configuration files
	#
	if [ "$IPBLOCKLIST_CTRL" -eq 1 ]
		then
			if [ -d "$IPBLOCKLIST_CONF_DIR" ]
				then
					log_action ""
					echo "> Consultation and completion of the report concerning the RBL lists managed by the local third-party RBL management service..."
					log_action "       > Consultation and completion of the report concerning the RBL lists managed by the local third-party RBL management service..."
					current_active_line=0
					#
					# Initialise output files
					: > "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp"
					: > "${DUPLICATES_RBL_FILE}"
					#
					if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
						then
							echo "" >> "${GLOBAL_INFO_FILE}"
					fi
					for rbl_name in "${active_ipblocklist_sets[@]}"
						do
							file="$IPBLOCKLIST_CONF_DIR/$rbl_name.conf"
							if [ -f "$file" ]
								then
									# Initialise output files
									: > "${ERRONEOUS_TIERCE_IPV4_FILE}"
									: > "${VALID_TIERCE_IPV4_FILE}"
									: > "${ERRONEOUS_TIERCE_IPV6_FILE}"
									: > "${VALID_TIERCE_IPV6_FILE}"
									#
									# Filter only IP addresses and subnets
									grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?' "$file" > "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp"
									#
									# Log erroneous subnets
									log_action "       - Log erroneous IPs and/or subnets in [ $rbl_name ] RBL..."
									erroneous_count=$(filter_erroneous_ips_subnets "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" "$rbl_name" "${VALID_TIERCE_IPV4_FILE}" "${ERRONEOUS_TIERCE_IPV4_FILE}" "${VALID_TIERCE_IPV6_FILE}" "${ERRONEOUS_TIERCE_IPV6_FILE}")
									log_action "         - Found [ $erroneous_count ] erroneous IPs and/or subnets in [ $rbl_name ] RBL"
									
									#
									# Concatenate valid IPv4 and IPv6 files in a temporary file with RBL names
									cat "${VALID_TIERCE_IPV4_FILE}" "${VALID_TIERCE_IPV6_FILE}" >> "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp"
									#
									# Count the number of occurrences in the resulting file for IPs and subnets
									ip_counts[$rbl_name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}(?=\s|$)' "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" | wc -l)
									network_counts[$rbl_name]=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}/([1-9]|[1-2][0-9]|3[0-2])(?=\s|$)' "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" | wc -l)
									ipv6_counts[$rbl_name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$' "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" | wc -l)
									ipv6_network_counts[$rbl_name]=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$' "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" | wc -l)
									#
									log_action "       - Success: Processed for [ $rbl_name ] with ${ip_counts[$rbl_name]} IPv4 IPs, ${network_counts[$rbl_name]} IPv4 networks, ${ipv6_counts[$rbl_name]} IPv6 IPs, and ${ipv6_network_counts[$rbl_name]} IPv6 networks"
									rbl_tierce_merged_count=$(cat "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" 2>/dev/null | wc -l)
									#
									if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
										then
											echo "IPs and subnets count for tierce RBL [ $rbl_name ]: ${ip_counts[$rbl_name]} IPv4 IPs, ${network_counts[$rbl_name]} IPv4 networks, ${ipv6_counts[$rbl_name]} IPv6 IPs, and ${ipv6_network_counts[$rbl_name]} IPv6 networks" >> "${GLOBAL_INFO_FILE}"
									fi
									ip_counts[$rbl_name]=0
									network_counts[$rbl_name]=0
									ipv6_counts[$rbl_name]=0
									ipv6_network_counts[$rbl_name]=0
									# Delete the temporary intermediate file
									[ -f "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp" ] && rm "${TEMP_RBL_DIR}/$rbl_name-filtered.tmp"
								else
									log_action "       - [ WARNING] Configuration file for Ipblocklist service [ $file ] not found for active ipset rule [ $rbl_name ]"
							fi
							log_action ""
							log_action "----------"
					done
					#
					# Count the number of occurrences in the resulting file for IPs and subnets
					ip_counts_global_tierce_RBL=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}(?=\s|$)' "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" | wc -l)
					network_counts_global_tierce_RBL=$(grep -oP '^[0-9]{1,3}(\.[0-9]{1,3}){3}/([1-9]|[1-2][0-9]|3[0-2])(?=\s|$)' "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" | wc -l)
					ipv6_counts_global_tierce_RBL=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)$' "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" | wc -l)
					ipv6_network_counts_global_tierce_RBL=$(grep -oP '^(([0-9a-fA-F]{1,4}:){1,7}|:)((:[0-9a-fA-F]{1,4}){1,7}|:)/([1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$' "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" | wc -l)
					#	
					log_action "       - Global count for tierce RBL: ${ip_counts_global_tierce_RBL} IPv4 IPs, ${network_counts_global_tierce_RBL} IPv4 networks, ${ipv6_counts_global_tierce_RBL} IPv6 IPs, and ${ipv6_network_counts_global_tierce_RBL} IPv6 networks"
					#
					echo # Add a new line after the final printf display in the console. This prevents the command line prompt from appearing directly after the last progress message.
					#
					# Write the duplicate file for alls RBls...
					log_action "     > Write the duplicate file for alls RBls..."
					# Import custom duplicate RBL file list... 
					cat "${REPORTS_DIR}/duplicate_custom_rbl.txt" > "${DUPLICATES_RBL_FILE}"
					# Check duplicate IPs and subnets for tierce RBL file...
					awk '
					{
						ip = $1;
						rbl = ($2 ? $2 : "UNKNOWN");
						if (ip in ips) {
							if (index(ips[ip], rbl) == 0) {
								ips[ip] = ips[ip] "," rbl;
								count[ip]++;
							}
						} else {
							ips[ip] = rbl;
							count[ip] = 1;
						}
					}
					END {
						for (ip in ips) {
							if (count[ip] > 1) {
								print ip, ips[ip];
							}
						}
					}' "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" >> "${DUPLICATES_RBL_FILE}"
					#
					duplicate_rbl_tierce_merged_count=$(cat "${DUPLICATES_RBL_FILE}" 2>/dev/null | wc -l)
					#
					if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
						then
							echo "" >> "${GLOBAL_INFO_FILE}"
							echo "Duplicate IPs and subnets count for tierce RBLs: [ $duplicate_rbl_tierce_merged_count ]" >> "${GLOBAL_INFO_FILE}"
					fi
					#
					# Delete the temporary intermediate file
					[ -f "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp" ] && rm "${TEMP_RBL_DIR}/merged_rbl_valid_tierce.tmp"
				else
					log_action "[ERROR] IPBLOCKLIST_CONF_DIR [ $IPBLOCKLIST_CONF_DIR ] does not exist. Skipping Ipblocklist verification."
			fi
		else
			log_action "[INFO] Ipblocklist verification [ variable IPBLOCKLIST_CTRL ] is disabled [ $IPBLOCKLIST_CTRL ]. Skipping."
	fi
	#
	##########################################################################################
	#
	#
	log_action "       > Check reference file and modify if necessary"
	if [ ! -s "${REFERENCE_FILE}" ]
		then
			log_action "       - Reference file [ ${REFERENCE_FILE} ] is missing or empty. Recreating from new filtered IPs list [ ${SORTED_NEW_IPS} ]."
			#
			# Attempt to recreate the reference file from new filtered IPs list $SORTED_NEW_IPS
			if cp "${SORTED_NEW_IPS}" "${REFERENCE_FILE}"
				then
					log_action "         - Reference file [ ${REFERENCE_FILE} ] recreated or populated successfully."
				else
					log_error "         - [ABORDING] Failed to recreate reference file [ ${REFERENCE_FILE} ]"
					log_error "         from new filtered IPs list [ ${SORTED_NEW_IPS} ]. Check permissions or disk space."
					return 1  # Return with error
			fi
		else
			log_action "         - Reference file [ ${REFERENCE_FILE} ] already exists and is not empty."
			if ! diff "${SORTED_NEW_IPS}" "${REFERENCE_FILE}" > /dev/null
				then
					log_action "           - Differences found between new filtered ips list [ ${SORTED_NEW_IPS} ] and reference file [ ${REFERENCE_FILE} ]"
					if cp "${SORTED_NEW_IPS}" "${REFERENCE_FILE}"
						then
							log_action "         - Move new filtered ips list [ ${SORTED_NEW_IPS} ] to reference file [ ${REFERENCE_FILE} ]. Updated the RBL reference file successfully."
							email_to_send=true
						else
							log_error "         - [ABORTING] Failed to move new filtered IPs list [ ${SORTED_NEW_IPS} ] to reference file [ ${REFERENCE_FILE} ]. Check permissions or disk space."
							return 1 # Return with error
					fi
				else
					log_action "           - No differences found between new filtered ips list [ ${SORTED_NEW_IPS} ] and reference file [ ${REFERENCE_FILE} ]"
			fi
	fi
	#
	[ -f "${TMP_FILE}" ] && rm "${TMP_FILE}" 
	[ -f "${TMP_FILE_WITH_RBLS}" ] && rm "${TMP_FILE_WITH_RBLS}"
	[ -f "${SORTED_NEW_IPS}" ] && rm "${SORTED_NEW_IPS}"
	#
}
#
# Function to ensure iptables child chain exists and add rules to it
add_iptables_child_rule() {
	local parent_chain=$1
	local child_chain=$2
	local ipset_name=$3
	local log_prefix=$4
	local log_rate=$5
	local log_burst=$6
	local action=$7
	#
	# Determine the correct iptables command based on the protocol family
	local iptables_cmd="iptables"
	if [[ "$ipset_name" == *"_V6"* ]]
		then
			iptables_cmd="ip6tables"
	fi
	#
	# Check if the correct protocol family is configured
	if [[ "$iptables_cmd" == "ip6tables" && ("$network_type" == "ipv4" || "$network_type" == "") ]]
		then
			log_action "     > IPv6 is not configured. Skipping IPv6 rule."
			return 0
	elif [[ "$iptables_cmd" == "iptables" && ("$network_type" == "ipv6" || "$network_type" == "") ]]
		then
			log_action "     > IPv4 is not configured. Skipping IPv4 rule."
			return 0
	fi
	#
	# Ensure the parent chain exists
	log_action "     > Checking existence of parent chain: $parent_chain"
	if ! $iptables_cmd -L $parent_chain > /dev/null 2>&1
		then
			log_error "     [ABORDING] Parent chain $parent_chain does not exist. Exiting..."
			return 1
	fi
	#
	# Ensure the child chain exists, create if it does not
	log_action "     > Checking and potentially creating child chain: $child_chain"
	if ! $iptables_cmd -L $child_chain > /dev/null 2>&1
		then
			$iptables_cmd -N $child_chain >> "${LOG_FILE}" 2>&1
			$iptables_cmd -A $parent_chain -j $child_chain >> "${LOG_FILE}" 2>&1
			log_action "     - Child chain $child_chain created and added to $parent_chain"
	fi
	#
	# Add rules to child chain
	if [[ "$log_prefix" != "" ]]
		then
			local log_rule=("$child_chain" "-m" "limit" "--limit" "$log_rate" "--limit-burst" "$log_burst" "-j" "LOG" "--log-prefix" "${log_prefix} ")
			log_action "     > Adding log rule to $child_chain"
			if ! $iptables_cmd -C "${log_rule[@]}" 2>/dev/null
				then
					$iptables_cmd -A "${log_rule[@]}" >> "${LOG_FILE}" 2>&1
					log_action "       - Log rule added: ${log_rule[*]}"
				else
					log_action "       - Log rule already exists: ${log_rule[*]}"
			fi
			#"${log_rule[@]}" expands each element of the array as a separate word, which is perfect for command execution as it preserves the exact arguments.
			#"${log_rule[*]}" expands all elements as a single word, with spaces between them, which makes it better for logging as a single string.
	fi
	#
	# Only add the action rule if a log prefix is NOT provided
	if [[ -z "$log_prefix" ]]
		then
			local action_rule=("$child_chain" "-j" "$action")
			log_action "     > Adding action rule to child chain: $child_chain"
			if ! $iptables_cmd -C "${action_rule[@]}" 2>/dev/null
				then
					$iptables_cmd -A "${action_rule[@]}" >> "${LOG_FILE}" 2>&1
					log_action "       - Action rule added: ${action_rule[*]}"
				else
					log_action "       - Action rule already exists: ${action_rule[*]}"
			fi
	fi
	log_action "     > Configuration complete for CHILD chain: $child_chain."
	log_action ""
	log_action "----------"
}
#
# Function to ensure iptables parent chain exists and add rules to it
add_iptables_parent_rule() {
	local parent_chain=$1
	local child_chain=$2
	local ipset_name=$3
	local direction=$4
	#
	# Determine the correct iptables command based on the protocol family
	local iptables_cmd="iptables"
	if [[ "$ipset_name" == *"_V6"* ]]
		then
			iptables_cmd="ip6tables"
	fi
	#
	# Check if the correct protocol family is configured
	if [[ "$iptables_cmd" == "ip6tables" && ("$network_type" == "ipv4" || "$network_type" == "") ]]
		then
			log_action "     > IPv6 is not configured. Skipping IPv6 rule."
			return 0
	elif [[ "$iptables_cmd" == "iptables" && ("$network_type" == "ipv6" || "$network_type" == "") ]]
		then
			log_action "     > IPv4 is not configured. Skipping IPv4 rule."
			return 0
	fi
	#
	# Ensure the child chain exists
	log_action "     > Checking existence of child chain: $child_chain"
	if ! $iptables_cmd -L $child_chain > /dev/null 2>&1
		then
			log_error "     [ABORDING] Child chain $child_chain does not exist. Exiting..."
			return 1
	else
		local action_rule=("$parent_chain" "-m" "set" "--match-set" "$ipset_name" "$direction" "-j" "$child_chain")
		log_action "     > Adding action rule to parent chain [ $parent_chain ] for child chain [ $child_chain ] "
		if ! $iptables_cmd -C "${action_rule[@]}" 2>/dev/null
			then
				$iptables_cmd -A "${action_rule[@]}" >> "${LOG_FILE}" 2>&1
				log_action "       - Action rule added: ${action_rule[*]}"
		else
			log_action "       - Action rule already exists: ${action_rule[*]}"
		fi
	fi
	#
	log_action "     > Configuration complete for PARENT chain: $parent_chain."
	log_action ""
	log_action "----------"
}
#
# Checking or updating Iptables rules
check_update_iptables_rules() {
	#
	# Checking or Updating iptables rules for inbound and outbound traffic on IPV4 Ipset custom list [ $IPV4_IPSET_NAME ]
	if [ "$network_type" == "ipv4" ] || [ "$network_type" == "dual" ]
		then
			log_action ""
			log_action "   > Checking or updating Iptables CHILD rules for inbound and outbound traffic on IPV4 Ipset custom list [ $IPV4_IPSET_NAME ]"
			add_iptables_child_rule "$IPV4_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV4_IPSET_NAME" "${IPTABLES_LOG_PREFIX}:" "$IPTABLES_LOG_LIMIT_RATE" "$IPTABLES_LOG_LIMIT_BURST" "LOG"
			add_iptables_child_rule "$IPV4_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV4_IPSET_NAME" "" "" "" "$IPTABLES_RULE"
			add_iptables_child_rule "$IPV4_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV4_IPSET_NAME" "${IPTABLES_LOG_PREFIX}:" "$IPTABLES_LOG_LIMIT_RATE" "$IPTABLES_LOG_LIMIT_BURST" "LOG"
			add_iptables_child_rule "$IPV4_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV4_IPSET_NAME" "" "" "" "$IPTABLES_RULE"
			#
			log_action ""
			log_action "   > Checking or updating Iptables PARENT rules for inbound and outbound traffic on IPV4 Ipset custom list [ $IPV4_IPSET_NAME ]"
			add_iptables_parent_rule "$IPV4_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV4_IPSET_NAME" "src"
			add_iptables_parent_rule "$IPV4_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV4_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV4_IPSET_NAME" "dst"
			log_action ""
			log_action "     > Iptables rules have been created or checked for Ipset custom list [ $IPV4_IPSET_NAME ]."
	fi
	#
	# Checking or Updating iptables rules for inbound and outbound traffic on IPV6 Ipset custom list [ $IPV6_IPSET_NAME ]
	if [ "$network_type" == "ipv6" ] || [ "$network_type" == "dual" ]
		then
			log_action ""
			log_action "   > Checking or updating Iptables CHILD rules for inbound and outbound traffic on IPV6 Ipset custom list [ $IPV6_IPSET_NAME ]"
			add_iptables_child_rule "$IPV6_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV6_IPSET_NAME" "${IPTABLES_LOG_PREFIX}:" "$IPTABLES_LOG_LIMIT_RATE" "$IPTABLES_LOG_LIMIT_BURST" "LOG"
			add_iptables_child_rule "$IPV6_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV6_IPSET_NAME" "" "" "" "$IPTABLES_RULE"
			add_iptables_child_rule "$IPV6_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV6_IPSET_NAME" "${IPTABLES_LOG_PREFIX}:" "$IPTABLES_LOG_LIMIT_RATE" "$IPTABLES_LOG_LIMIT_BURST" "LOG"
			add_iptables_child_rule "$IPV6_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV6_IPSET_NAME" "" "" "" "$IPTABLES_RULE"
			#
			log_action ""
			log_action "   > Checking or updating Iptables PARENT rules for inbound and outbound traffic on IPV6 Ipset custom list [ $IPV6_IPSET_NAME ]"
			add_iptables_parent_rule "$IPV6_IPTABLES_PARENT_CUSTOM_IN_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_IN_CHAIN" "$IPV6_IPSET_NAME" "src"
			add_iptables_parent_rule "$IPV6_IPTABLES_PARENT_CUSTOM_OUT_CHAIN" "$IPV6_IPTABLES_CHILD_CUSTOM_OUT_CHAIN" "$IPV6_IPSET_NAME" "dst"
			log_action ""
			log_action "     > Iptables rules have been created or checked for Ipset custom list [ $IPV6_IPSET_NAME ]."
	fi
}
#
# Updating IPSET rules...
update_ipset() {
	log_action "       > Delete current list for $IPV4_IPSET_NAME and $IPV6_IPSET_NAME"
	if [ "$network_type" == "ipv4" ] || [ "$network_type" == "dual" ]
		then
			ipset flush $IPV4_IPSET_NAME >> "${LOG_FILE}" 2>&1
	fi
	if [ "$network_type" == "ipv6" ] || [ "$network_type" == "dual" ]
		then
			ipset flush $IPV6_IPSET_NAME >> "${LOG_FILE}" 2>&1
	fi
	#
	log_action "       > Add new IPs to $IPV4_IPSET_NAME and $IPV6_IPSET_NAME..."
	total_lines=$(grep -vP '^(#|$)' "${REFERENCE_FILE}" | wc -l)
	current_line=0
	#
	grep -vP '^(#|$)' "${REFERENCE_FILE}" | while read -r ip
		do
			if [[ "$ip" =~ : ]]
				then
					if [ "$network_type" == "ipv6" ] || [ "$network_type" == "dual" ]
						then
							((current_line++))
							printf "\r\033[K> Adding IPv6 to custom ipset RBL list [ $IPV6_IPSET_NAME ] - Processing line %d/%d: %s" "$current_line" "$total_lines" "$ip"
							# Force immediate display
							echo -n ""
							ipset add "$IPV6_IPSET_NAME" "$ip" >> "${LOG_FILE}" 2>&1
					fi
				else
					if [ "$network_type" == "ipv4" ] || [ "$network_type" == "dual" ]
						then
							((current_line++))
							printf "\r\033[K> Adding IPv4 to custom ipset RBL list [ $IPV4_IPSET_NAME ] - Processing line %d/%d: %s" "$current_line" "$total_lines" "$ip"
							# Force immediate display
							echo -n ""
							ipset add "$IPV4_IPSET_NAME" "$ip" >> "${LOG_FILE}" 2>&1
					fi
			fi
	done
	#
	if [ "$network_type" == "ipv4" ] || [ "$network_type" == "dual" ]
		then
			log_action "     > Save ipset name [ $IPV4_IPSET_NAME ] to ipset file [ ${IPV4_IPSET_SAVE_FILE} ]..."
			ipset save $IPV4_IPSET_NAME > $IPV4_IPSET_SAVE_FILE 2>> "${LOG_FILE}"
			log_action "     > Restore ipset name [ $IPV4_IPSET_NAME ] from ipset file [ ${IPV4_IPSET_SAVE_FILE} ]..."
			ipset restore -! < ${IPV4_IPSET_SAVE_FILE} 2>> "${LOG_FILE}"
	fi
	#
	if [ "$network_type" == "ipv6" ] || [ "$network_type" == "dual" ]
		then
			log_action "     > Save ipset name [ $IPV6_IPSET_NAME ] to ipset file [ ${IPV6_IPSET_SAVE_FILE} ]..."
			ipset save $IPV6_IPSET_NAME > ${IPV6_IPSET_SAVE_FILE} 2>> "${LOG_FILE}"
			log_action "     > Restore ipset name [ $IPV6_IPSET_NAME ] from ipset file [ ${IPV6_IPSET_SAVE_FILE} ]..."
			ipset restore -! < ${IPV6_IPSET_SAVE_FILE} 2>> "${LOG_FILE}"
	fi
	#
	log_action "     > Checking or updating IPTABLES rules."
	check_update_iptables_rules
	email_to_send=true
}
#
# Implement IPs from the reference file
implement_ips_from_file() {
	# Check if IPSET exists before creating
	log_action "     > Check if IPSET exists before creating"
	#
	if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv4" ]
		then
			if ! ipset list "$IPV4_IPSET_NAME" &>/dev/null
				then
					log_action "       - Creating IPSET $IPV4_IPSET_NAME as it does not exist."
					ipset create $IPV4_IPSET_NAME hash:net family inet >> "${LOG_FILE}" 2>&1
				else
					log_action "       - IPSET $IPV4_IPSET_NAME already exists. Not creating."
			fi
	fi
	#
	if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv6" ]
		then
			if ! ipset list "$IPV6_IPSET_NAME" &>/dev/null
				then
					log_action "       - Creating IPSET $IPV6_IPSET_NAME as it does not exist."
					ipset create $IPV6_IPSET_NAME hash:net family inet6 >> "${LOG_FILE}" 2>&1
				else
					log_action "       - IPSET $IPV6_IPSET_NAME already exists. Not creating."
			fi
	fi
	#
	# Check if the IPV4_IPSET save file exists
	if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv4" ]
		then
			log_action "     > Check if the IPV4_IPSET save file exists"
			if [ -f "${IPV4_IPSET_SAVE_FILE}" ]
				then
					log_action "       - ${IPV4_IPSET_SAVE_FILE} exists...continuing"
				else
					log_action "       - ${IPV4_IPSET_SAVE_FILE} does not exist, creating new one."
					# Ensure the directory exists and create it if it doesn't
					if [ ! -d "$(dirname "${IPV4_IPSET_SAVE_FILE}")" ]
						then
							mkdir -p "$(dirname "${IPV4_IPSET_SAVE_FILE}")"
					fi
					touch "${IPV4_IPSET_SAVE_FILE}"  # This step ensures that the file exists for future operations
			fi
	fi
	#
	# Check if the IPV6_IPSET save file exists
	if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv6" ]
		then
			log_action "     > Check if the IPV6_IPSET save file exists"
			if [ -f "${IPV6_IPSET_SAVE_FILE}" ]
				then
					log_action "       - ${IPV6_IPSET_SAVE_FILE} exists...continuing"
				else
					log_action "       - ${IPV6_IPSET_SAVE_FILE} does not exist, creating new one."
					# Ensure the directory exists and create it if it doesn't
					if [ ! -d "$(dirname "${IPV6_IPSET_SAVE_FILE}")" ]
						then
							mkdir -p "$(dirname "${IPV6_IPSET_SAVE_FILE}")"
					fi
					touch "${IPV6_IPSET_SAVE_FILE}"  # This step ensures that the file exists for future operations
			fi
	fi
	#
	# Now check the conditions related to updating based on ${SORTED_CURRENT_IPS} and ${REFERENCE_FILE}
	log_action "     > Check the conditions related to updating based on actual IPSET blacklist [ $IPV4_IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] charged on [ $SORTED_CURRENT_IPS ]"
	log_action "       and reference file [ $REFERENCE_FILE ]"
	if [ -f "${REFERENCE_FILE}" ]
		then
			if [ -s "${SORTED_CURRENT_IPS}" ] && [ -s "${REFERENCE_FILE}" ]
				then
					# Create temporary sorted files
					sorted_current_ips_tmp=$(mktemp)
					sorted_reference_file_tmp=$(mktemp)
					#
					# Sorting files
					sort "${SORTED_CURRENT_IPS}" > "${sorted_current_ips_tmp}"
					sort "${REFERENCE_FILE}" > "${sorted_reference_file_tmp}"

					if ! diff "${sorted_current_ips_tmp}" "${sorted_reference_file_tmp}" > /dev/null
						then
							log_action ""
							log_action "       - Differences found between actual IPSET blacklist [ $IPV4_IPSET_NAME ] and [ $IPV6_IPSET_NAME ] charged on [ ${SORTED_CURRENT_IPS} ]"
							log_action "         and reference file [ ${REFERENCE_FILE} ]. Updating blacklist [ $IPV4_IPSET_NAME ] and [ $IPV6_IPSET_NAME ]..."
							log_action ""
							log_action "     > Checking or updating IPSET rules."
							update_ipset
						else
							log_action ""
							log_action "       - No differences found between actual IPSET blacklist [ $IPV4_IPSET_NAME ] and [ $IPV6_IPSET_NAME ] charged on [ ${SORTED_CURRENT_IPS} ]"
							log_action "         and reference file [ ${REFERENCE_FILE} ]."
							log_action "         No update needed. Blacklist [ $IPV4_IPSET_NAME ] and [ $IPV6_IPSET_NAME ] unchanged."
							log_action ""
							log_action "     > Checking or updating IPTABLES rules."
							check_update_iptables_rules
					fi
					# Delete temporary sorted files
					rm -f "${sorted_current_ips_tmp}" "{$sorted_reference_file_tmp}"
				elif [ ! -s "${SORTED_CURRENT_IPS}" ]
					then
						if [ -s "${REFERENCE_FILE}" ]
							then
								log_action ""
								log_action "       - Reference file [ ${REFERENCE_FILE} ] exists AND is not empty. Updating based on reference..."
								log_action ""
								log_action "     > Checking or updating IPSET rules."
								update_ipset
							else
								log_action ""
								log_error "       - [ABORTING] actual IPSET blacklist [ ${SORTED_CURRENT_IPS} ] is empty AND reference file [ ${REFERENCE_FILE} ] is empty."
								log_error "         Please execute with -u option to update."
								return 1 # Return with error
						fi
				fi
		else
			log_action ""
			log_action "       - [WARNING] Reference file [ ${REFERENCE_FILE} ] does not exist, Attempt to execute the -u (update) option automatically..."
			if [ "$attempt_update" -eq 1 ]
				then
					log_error "         - The update execution has already been attempted. An error occurs when attempting to update the RBLs !"
					return 1 # Return with error
				else
					update_rbl_list
					attempt_update=1
					implement_ips_from_file
			fi
	fi
}
#
# -----------------
# -----------------
#
#
#
#
#
##############
# Start script
##############
#
#
# Check if the PID file already exists
if [ -e "${PIDFILE}" ]
	then
		# Get the age of the PID file in seconds
		file_age=$(($(date +%s) - $(stat -c %Y "${PIDFILE}")))
		#
		# Check if PID file is older than MAX_AGE
		if [ "$file_age" -gt "$MAX_AGE" ]
			then
				echo ""
				echo "[WARNING] The PID file is older than $((MAX_AGE / 3600)) hours. Delete it and continue."
				echo ""
				cleanup
			else
				echo ""
				echo "[INFO] Another instance of this script is already running. We can't go on"
				echo "Try again later"
				echo ""
				exit 1
		fi
fi
#
# Créer le fichier PID
echo $$ > "${PIDFILE}"
#
# Ensure the PID file is deleted when the script exits or is interrupted
trap cleanup EXIT
trap 'cleanup; echo; exit 1' SIGHUP SIGINT SIGTERM
#
# Clean log file
> "${LOG_FILE}"
#
# Get the user and UID
CURRENT_USER=$(whoami)
CURRENT_UID=$UID
#
echo "" >> "${LOG_FILE}"
log_action ""
log_action "+++++ Script start at: `date` by user: $CURRENT_USER (UID: $CURRENT_UID) +++++"
log_action ""
echo ""
echo "+++++ Script start at: `date` by user: $CURRENT_USER (UID: $CURRENT_UID) +++++"
echo ""
#
# Creating temporary directory
if [ ! -d "${TEMP_RBL_DIR}" ]
	then
		mkdir -p "${TEMP_RBL_DIR}"
fi
# Creating reports directory
if [ ! -d "${REPORTS_DIR}" ]
	then
		mkdir -p "${REPORTS_DIR}"
fi
#
# Initialise the network_type variable
network_type=""
#
# Check for the presence of IPv4 addresses interface
if ip addr show | grep -q "inet "
	then
		log_action "[INFO] IPv4 is configured for this computer"
		network_type="ipv4"
fi
#
# Check for the presence of IPv6 addresses interface
if ip -6 addr show | grep -q "inet6 "
	then
		log_action "[INFO] IPv6 is configured for this computer"
		if [ -z "$network_type" ]
			then
				network_type="ipv6"
			else
				network_type="dual"
		fi
fi
#
# Check that no address is configured for interfaces
if [ -z "$network_type" ]
	then
		log_error "[ERROR] Neither IPv4 nor IPv6 is configured for this computer"
		exit 1
fi
#
log_action "[INFO] Network type determined: $network_type"
#
# Save current ipset to file and sort it if it exists
log_action ""
#
if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv4" ]
	then
		log_action "> Save current ipset [ $IPV4_IPSET_NAME ] to file [ ${SORTED_CURRENT_IPS} ] and sort it"
		if ipset list $IPV4_IPSET_NAME > /dev/null 2>&1
			then
				log_action "   - IPSet [ $IPV4_IPSET_NAME ] exist, create a new pre-sorted list [ ${IPV4_SORTED_CURRENT_IPS} ]"
				ipset save $IPV4_IPSET_NAME | grep -oP '(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?' | sort -u > "${IPV4_SORTED_CURRENT_IPS}"
			else
				log_action "   - IPSet [ $IPV4_IPSET_NAME ] does not exist, skipping save and create empty file for pre-sorted list [ ${IPV4_SORTED_CURRENT_IPS} ]"
				touch "${IPV4_SORTED_CURRENT_IPS}"
		fi
		cat "${IPV4_SORTED_CURRENT_IPS}" > "${SORTED_CURRENT_IPS}"
fi
#
if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv6" ]
	then
		log_action "> Save current ipset [ $IPV6_IPSET_NAME ] to file [ ${SORTED_CURRENT_IPS} ] and sort it"
		if ipset list $IPV6_IPSET_NAME > /dev/null 2>&1
			then
				log_action "   - IPSet [ $IPV6_IPSET_NAME ] exist, create a new pre-sorted list [ ${IPV6_SORTED_CURRENT_IPS} ]"
				ipset save $IPV6_IPSET_NAME | grep -oP '(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?' | sort -u >> "${IPV6_SORTED_CURRENT_IPS}"
			else
				log_action "   - IPSet [ $IPV6_IPSET_NAME ] does not exist, skipping save and create empty file for pre-sorted list [ ${IPV6_SORTED_CURRENT_IPS} ]"
				touch "${IPV6_SORTED_CURRENT_IPS}"
		fi
		cat "${IPV6_SORTED_CURRENT_IPS}" >> "${SORTED_CURRENT_IPS}"
fi
#
# Count the current IPs and subnets in the single Ipset list [ $IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] BEFORE the update process.
log_action ""
log_action "> Count the current IPs and subnets in the single Ipset list [ $IPV4_IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] BEFORE the update process."
initial_counts=$(count_ips_and_subnets ${SORTED_CURRENT_IPS})
log_action "   - Actual [ $IPV4_IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] counts: $initial_counts"
#
# Execute based on flags
if $check_presence_custom_RBL
	then
		FILL_GLOBAL_INFO_FILE=0
		log_action ""
		log_action "> Option -c chosen ...check presence of custom ipset list..."
		echo ""
		echo "> Option -c chosen ...check presence of custom ipset list..."
		#
		if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv4" ]
			then
				if ! ipset list "$IPV4_IPSET_NAME" &>/dev/null
					then
						echo "   - The custom RBL [ $IPV4_IPSET_NAME ] not found on ipset list...create custom RBL [ $IPV4_IPSET_NAME ]"
						log_action "   - The custom RBL [ $IPV4_IPSET_NAME ] not found on ipset list...create custom RBL [ $IPV4_IPSET_NAME ]"
						implement_ips_from_file
					else
						echo "   - The custom RBL [ $IPV4_IPSET_NAME ]found on ipset list...nothing to do."
						log_action "   - The custom RBL [ $IPV4_IPSET_NAME ]found on ipset list...nothing to do."
				fi
		fi
		#
		if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv6" ]
			then
				if ! ipset list "$IPV6_IPSET_NAME" &>/dev/null
					then
						echo "   - The custom RBL [ $IPV6_IPSET_NAME ] not found on ipset list...create custom RBL [ $IPV6_IPSET_NAME ]"
						log_action "   - The custom RBL [ $IPV6_IPSET_NAME ] not found on ipset list...create custom RBL [ $IPV6_IPSET_NAME ]"
						implement_ips_from_file
					else
						echo "   - The custom RBL [ $IPV6_IPSET_NAME ]found on ipset list...nothing to do"
						log_action "   - The custom RBL [ $IPV6_IPSET_NAME ]found on ipset list...nothing to do"
				fi
		fi
fi
if $update_only
	then
		log_action ""
		log_action "> Option -u chosen ...update RBL List..."
		echo ""
		echo "> > Option -u chosen ...update RBL List..."
		update_rbl_list
fi
#
#
if $implement_ips
	then
		log_action ""
		log_action "> Option -i chosen ...implement IPs from file..."
		echo ""
		echo "> Option -i chosen ...implement IPs from file..."
		implement_ips_from_file
fi
#
#
log_action ""
log_action "> New IPs and subnets details for all Ipset lists after update..."
#
# Get the full list of ipset details
ipset_list_output=$(ipset list)
#
# Use awk to process the output and extract details
echo "$ipset_list_output" | awk '
BEGIN {
	print "IPSet Details:"
	print "---------------------"
	totalEntries = 0
}

/^Name:/ {
	name = $2
}

/^Number of entries:/ {
	entries = $4
	totalEntries += entries
}

/^Size in memory:/ {
	memory = $4 " " $5
}

/^Members:/ {
	print "Name: " name
	print "Entries: " entries
	print "Size in Memory: " memory
	print "---------------------"
}

END {
	print "\nTotal Entries: " totalEntries
}' >> "${LOG_FILE}"
#
echo "" >> "${LOG_FILE}"
#
# Count the current IPs and subnets in the single Ipset list [ $IPV4_IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] AFTER the update process.
log_action ""
log_action "> Count the current IPs and subnets in the single Ipset list [ $IPV4_IPSET_NAME ] and/or [ $IPV6_IPSET_NAME ] AFTER the update process."
#
if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv4" ]
	then
		log_action "> Save current ipset [ $IPV4_IPSET_NAME ] to file [ ${CURRENT_COUNT_CUSTOM_IPSET} ] and sort it"
		if ipset list $IPV4_IPSET_NAME > /dev/null 2>&1
			then
				log_action "   - IPSet [ $IPV4_IPSET_NAME ] exist, create a new pre-sorted list [ ${CURRENT_IPV4_COUNT_CUSTOM_IPSET} ]"
				ipset save $IPV4_IPSET_NAME | grep -oP '(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?' | sort -u > "${CURRENT_IPV4_COUNT_CUSTOM_IPSET}"
			else
				log_action "   - IPSet [ $IPV4_IPSET_NAME ] does not exist, skipping save and create empty file for pre-sorted list [ ${CURRENT_IPV4_COUNT_CUSTOM_IPSET} ]"
				touch "${CURRENT_IPV4_COUNT_CUSTOM_IPSET}"
		fi
		cat "${CURRENT_IPV4_COUNT_CUSTOM_IPSET}" > "${CURRENT_COUNT_CUSTOM_IPSET}"
fi
#
if [ "$network_type" == "dual" ] || [ "$network_type" == "ipv6" ]
	then
		log_action "> Save current ipset [ $IPV6_IPSET_NAME ] to file [ ${CURRENT_COUNT_CUSTOM_IPSET} ] and sort it"
		if ipset list $IPV6_IPSET_NAME > /dev/null 2>&1
			then
				log_action "   - IPSet [ $IPV6_IPSET_NAME ] exist, create a new pre-sorted list [ ${CURRENT_IPV6_COUNT_CUSTOM_IPSET} ]"
				ipset save $IPV6_IPSET_NAME | grep -oP '(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?' | sort -u >> "${CURRENT_IPV6_COUNT_CUSTOM_IPSET}"
			else
				log_action "   - IPSet [ $IPV6_IPSET_NAME ] does not exist, skipping save and create empty file for pre-sorted list [ ${CURRENT_IPV6_COUNT_CUSTOM_IPSET} ]"
				touch "${CURRENT_IPV6_COUNT_CUSTOM_IPSET}"
		fi
		cat "${CURRENT_IPV6_COUNT_CUSTOM_IPSET}" >> "${CURRENT_COUNT_CUSTOM_IPSET}"
fi
last_counts=$(count_ips_and_subnets ${CURRENT_COUNT_CUSTOM_IPSET})
log_action "   - Actual custom RBL reference file counts: [ $last_counts ]"
#
# Check and delete temporary files, if any
[ -f "${CURRENT_IPV4_COUNT_CUSTOM_IPSET}" ] && rm "${CURRENT_IPV4_COUNT_CUSTOM_IPSET}"
[ -f "${CURRENT_IPV6_COUNT_CUSTOM_IPSET}" ] && rm "${CURRENT_IPV6_COUNT_CUSTOM_IPSET}"
[ -f "${CURRENT_COUNT_CUSTOM_IPSET}" ] && rm "${CURRENT_COUNT_CUSTOM_IPSET}"
#
if [ "$FILL_GLOBAL_INFO_FILE" -eq 1 ]
	then
		echo "" >> "${GLOBAL_INFO_FILE}"
		echo "Actual custom RBL reference file counts: [ $last_counts ]" >> "${GLOBAL_INFO_FILE}"
fi
#
# Check and send email if changes were detected and ADMIN_MAIL is set
if $email_to_send || $error_occurred
	then
		# Send e-mail
		log_action ""
		log_action "> Send e-mail to admin [ $ADMIN_MAIL ]"
		log_action "> Script execution completed"
		log_action ""
		log_action "+++++ script end at: $(date) +++++"
		echo ""
		echo "> Send e-mail to admin [ $ADMIN_MAIL ]"
		echo "> Script execution completed"
		echo ""
		echo "+++++ script end at: $(date) +++++"
		echo "" >> "${LOG_FILE}"
		send_mail
	else
		log_action ""
		log_action "> Script execution completed"
		log_action ""
		log_action "+++++ script end at: $(date) +++++"
		echo ""
		echo "> Script execution completed"
		echo ""
		echo "+++++ script end at: $(date) +++++"
		echo "" >> "${LOG_FILE}"
fi
#
if [ -d "$TEMP_RBL_DIR" ]
	then
		echo ""
		rm -rf "$TEMP_RBL_DIR"
fi
#
exit 0
