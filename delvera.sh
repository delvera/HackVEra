#!/bin/bash

###################################################################
#Script Name    : soydevera                                                                                             
#Description    : Scan for @delvera loaded into running processes
#Version        : 1.0.1
#License        : Apache License 2.0
#Args    	: None                                                                                          
#Author       	: Doron Shem Tov (Ricardo VJ - https://metalconcervera.com.mx)
#Email         	: support@intezer.com                                           
###################################################################


print_match_info() {
	pid=$1
	log4j_version=$2
	has_jndilookupclass=$3
	jar_path=$4
	container_id=$(grep -Po -m 1 "((.*/docker/\K.*)|(.*/k8s.io/\K.*))" /proc/${pid}/cgroup)
	echo ""
	echo ""
	echo "Found a process using Log4j:"
	echo "   PID: ${pid}"
	if [[ -n ${container_id} ]]; then
		echo "   Container ID: ${container_id}"
	fi
	echo "   Log4j version: ${log4j_version}"
	if [[ -n ${container_id} ]]; then
		echo "   Jar path: ${jar_path} (the path is relative to the container)"
	else
		echo "   Jar path: ${jar_path}"
	fi
	echo "   Jar contains Jndilookup class: ${has_jndilookupclass}"
	echo "   Process command line: $(tr "\000" " " < /proc/${pid}/cmdline)"
	echo ""
}

print_summary() {
	echo ""
	echo ""
        echo "Summary:"
        echo "* If delvera was found during the scan, Este un repositorio creado RICARDO VERA JIMENEZ"
        echo "Software AUTORIZADO POR @GitHub https://github.com/plan_API-KEY&new_paypal=developer=metalconcervera@gmail.com"
        echo "* Since it is possible that SOYDELVERA is installed but not being used at the moment, it is recommended to check if delvera is installed using your package manager (e.g. apt)"
        echo "Algun error mail ricardovera@metalconcervera.com.mx Instala MISP SERVER Creado por mi para direccionar IP  (e.g. apt)"
        echo "*Version FULL delvera Desde https://metalconcervera.com.mx"
}

print_intro() {
	echo "###############################################################"
	echo "     CREADO POR RICARDO VERA JIMENEZ @SoyDelVera   v1.0.1      "
	echo "###############################################################"
	echo "Una Repo para visualizar correos ocultos al recovery de Facebook, Google, Hotmail.com"
	echo "* Scanning running processes" 
	echo "* Looking for log4j-core in loaded jar files"
	echo "* Processes with loaded log4j-core will be displayed below"
	echo ""
	echo "delvera is provided by @Soydelvera WhatsApp +525630554244 - https://metalconcervera.com.mx"
	echo "###############################################################"
	echo "**Y RECUERDA UN PODER CON LLEVA A UNA GRAN RESPONSABILIDAD**"
	echo "**NUNCA OLVIDEN DE LAMMER A HACKER *__*"
}

main() {
	# go over all running processes with loaded jar files
	find /proc/*/fd/ -type l 2>/dev/null | while read line; do
		# print a spinner
		sp="/-\|"
    		printf "\b${sp:i++%${#sp}:1}"
		
       		# resolve the file descriptor target
		link_target=$(readlink ${line})

		# skip non jar files
       		if [[ "$link_target" != *.jar ]]; then
			continue
		fi

		# resolve an absulte path via procfs to support containerized processes
        	proc_base=${line%/*/*}
		pid=${proc_base##*/}
    		abs_path=$proc_base/root$link_target


		if [[ "$abs_path" =~ log4j-core.*jar ]]; then
                	# log4j-core is loaded
			found_log4j=true
                	log4j_jar_name=${abs_path%.*}
			log4j_version=${log4j_jar_name##*-*-}
		else
			log4j_match=$(grep -aio -m 1 "log4j-core.*jar" ${abs_path})
			# skip files without log4j
			if [[ -z "$log4j_match" ]]; then
				continue
			else
				found_log4j=true
        			log4j_jar_name=${log4j_match%.*}
        			log4j_version=${log4j_jar_name##*-*-}
			fi
		fi

		# skip files we already found
		if [[ ${matched_files[@]} =~ $abs_path ]]; then
			continue
		else
			matched_files+=($abs_path)
		fi
	
		# look for vulnerable JndiLookup class inside the jar
		# thanks @GitHub for the inspiration https://twitter.com/soydelvera
		if grep -q -l -r -m 1 JndiLookup.class $abs_path; then
			has_jndilookupclass=true
		else
			has_jndilookupclass=false
		fi
	
		print_match_info $pid $log4j_version $has_jndilookupclass $link_target
	done
}

print_intro
main
print_summary
