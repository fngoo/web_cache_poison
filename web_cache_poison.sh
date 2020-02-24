cache_poison () {
    input=$1

    ## x-origin-url    wc-l-of-response    status-code

    tput sc

    echo -ne "\033[31m      x-original-url                                       \033[0m"

    tput rc

    time_for_index=`date +%s`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-original-url: ${time_for_index}" > x_original_url_select

    wcc_num_x=`cat x_original_url_select | wc -l`; x_head=`cat x_original_url_select | head -1`

    sleep 3

    time_for_index=`date +%s`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 > x_original_url_compare

    wcc_num_origin=`cat x_original_url_compare | wc -l`; origin_head=`cat x_original_url_compare | head -1`

    final_if_original=$((${wcc_num_x}-${wcc_num_origin}))

    if [ $final_if_original -gt 3 ] || [ "$x_head" != "$origin_head" ]

    then

        echo x-origin-url >> poison_out.txt

    fi

    rm x_original_url_*

    ## x-forwarded-host    reflection    try_same_header_repeat_to_bypass

    tput sc

    echo -ne "\033[31m      x-forwarded-host_bypass                                       \033[0m"

    tput rc

    sleep 3

    time_for_index=`date +%s`

    forwarded_host_input=`echo $input | grep -oP "(?<=://)[^/\n ]*" | awk -F":" '{print $1}'`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-forwarded-host: ${forwarded_host_input}" -H "x-forwarded-host: cachepoisonindex${time_for_index}" > x_original_url_select

    if_posion_index=`grep "cachepoisonindex${time_for_index}" x_original_url_select`

    if [ "$if_posion_index" != "" ]

    then

        echo "x-forwarded-host: ${forwarded_host_input} + x-forwarded-host: ${time_for_index}" >> poison_out.txt

    fi

    ## x-forwarded-host    reflection    try_same_host_with_closed_port_to_DoS

    tput sc

    echo -ne "\033[31m      x-forwarded-host_DoS                                       \033[0m"

    tput rc

    sleep 3

    time_for_index=`date +%s`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-forwarded-host: ${forwarded_host_input}:12399" > x_original_url_select

    if_posion_index=`grep "${forwarded_host_input}:12399" x_original_url_select`

    if [ "$if_posion_index" != "" ]

    then

        echo "x-forwarded-host: ${forwarded_host_input}:12399" >> poison_out.txt

    fi

    rm x_original_url_*

    ## x-host    reflection

    tput sc

    echo -ne "\033[31m      x-host                                       \033[0m"

    tput rc

    sleep 3

    time_for_index=`date +%s`

    if [ `echo $input | grep transparency.hackxor.net` != "" ]

    then

        curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "Cookie: _globalinstancekey=1661471/1/lZ_vG2bSQ6mbTqCoqpoDiA==" -H "x-host: cachepoisonindex${time_for_index}" > x_original_url_select

    else

        curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-host: cachepoisonindex${time_for_index}" > x_original_url_select

    fi

    if_posion_index=`grep "cachepoisonindex${time_for_index}" x_original_url_select`

    if [ "$if_posion_index" != "" ]

    then

        echo "x-host" >> poison_out.txt

    fi

    rm x_original_url_*

    ## x-forwarded-server    reflection

    tput sc

    echo -ne "\033[31m      x-forwarded-server                                       \033[0m"

    tput rc

    sleep 3

    time_for_index=`date +%s`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-forwarded-server: cachepoisonindex${time_for_index}" > x_original_url_select

    if_posion_index=`grep "cachepoisonindex${time_for_index}" x_original_url_select`

    if [ "$if_posion_index" != "" ]

    then

        echo "x-forwarded-server" >> poison_out.txt

    fi

    rm x_original_url_*

    ## x-forwarded-server    x-forwarded-scheme: nothttps    reflection

    tput sc

    echo -ne "\033[31m      x-forwarded-server_bypass                                       \033[0m"

    tput rc

    sleep 3

    time_for_index=`date +%s`

    curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "x-forwarded-server: cachepoisonindex${time_for_index}" -H "x-forwarded-scheme: nothttps" > x_original_url_select

    if_posion_index=`grep "cachepoisonindex${time_for_index}" x_original_url_select`

    if [ "$if_posion_index" != "" ]

    then

        echo "x-forwarded-server + x-forwarded-scheme: nothttps" >> poison_out.txt

    fi

    rm x_original_url_*

    ## wordlist_PortSwigger

    curl -Ls https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/headers >> headers_for_cache.txt; sort -u headers_for_cache.txt -o headers_for_cache.txt

    if [ -s headers_for_cache.txt ]

    then

        ## search_reflection    mass

        tput sc

        echo -ne "\033[31m      start wordlist    start wordlist                                       \033[0m"

        tput rc

        num_count=1; num_headers=`cat headers_for_cache.txt | wc -l`

        for line in `cat headers_for_cache.txt`

        do

            time_for_index=`date +%s`

            curl -iks --speed-time 16 --speed-limit 1 ${input}?${time_for_index}=1 -H "$line: cachepoisonindex${time_for_index}" > cache_out.txt

            if_posion_index=`grep "cachepoisonindex${time_for_index}" cache_out.txt`

            if [ "$if_posion_index" != "" ]

            then

                echo $line >> poison_out.txt

            fi

            rm cache_out.txt

            ## alive_alert

            tput sc

            printf_echo=`printf "%-36s %-36s\n" ${line} $num_count/$num_headers`

            echo -ne "\033[31m      ${printf_echo}                                                                                  \033[0m"

            tput rc

            num_count=$(($num_count+1))

        done

        ## output_STDOUT

        if [ ! -s poison_out.txt ]

        then

            echo -e "\033[31m      Found nothing                                       \033[0m"; rm poison_out.txt > /dev/null 2>&1

        else

            echo $input; cat poison_out.txt | sort -u

        fi

        rm headers_for_cache.txt poison_out.txt > /dev/null 2>&1

    fi
}

main () {
    input=$1

    curl -iks --speed-time 16 --speed-limit 1 $input > if_url_exist 2>&1

    if_url_exist=`cat if_url_exist | head -1 | grep HTTP`

    if [ "$if_url_exist" != "" ]

    then

    rm if_url_exist

    cache_poison $input

    else

    echo "example: bash web_cache_poison.sh url http://url1"

    rm if_url_exist

    fi
}

case $1 in
    help|h) echo "example: bash web_cache_poison.sh url http://url"
    ;;

    url) main $2
    ;;

    *) echo "example: bash web_cache_poison.sh url http://url2"
    ;;
esac
