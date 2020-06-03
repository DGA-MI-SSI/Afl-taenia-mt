#!/bin/bash

# This table will contain our conf values on a tab_conf["key"]=value basis
declare -A tab_conf

# add an already validated line to tab_conf
function add_line_to_tab_conf()
{
    if [ $# -ne 1 ] 
    then
        printf "Usage: add_line_to_tab_conf line_to_add\n"
        return 1
    fi

    line_to_add=$1
    key=$(echo $line_to_add | cut -f1 -d=)
    value=$(echo $line_to_add | cut -f2 -d=)
    tab_conf["$key"]="$value"
}

# Print the string in red
function print_error()
{
    if [ $# -ne 1 ] 
    then
        printf "Usage: print_error string\n"
        return 1
    fi
    printf "\033[01;31m%s\033[00m\n" "$1"
}

# Validate a line and pass it to add_line_to_tab_conf()
function parse_line()
{
    if [ $# -ne 2 ] 
    then
        printf "Usage: parse_line line_to_parse line_number\n"
        return 1
    fi

    comment_regex='^[[:space:]]*#'
    empty_regex="^$"
    valid_regex="^[0-9a-zA-Z_]+=[-0-9a-zA-Z\s\_\/]+"

    line=$1
    line_number=$2
    if ! [[ $line =~ $empty_regex ]]
    then
        if ! [[ $line =~ $comment_regex ]]
        then
            if [[ $line =~ $valid_regex ]]
            then
                add_line_to_tab_conf "$line"
            else
                string=$(printf "Invalid configuration syntax l%d: %s" "$line_number" "$line")
                print_error "$string"
            fi
        fi
    fi

    return 0
}

# Validate that all mandatory variables are set
function validate_mandatory_variables()
{
    #local abort_exec=0
    for key in "${tab_mandatory[@]}" 
    do
        if [ -z "${tab_conf["$key"]}" ]
        then
            string=$(printf "%s key is missing, please add a value to this configuration key like so: %s=<VALUE>" "$key" "$key")
            print_error "$string"
            abort_exec=true
        fi
    done
    if [ "$abort_exec" == true ]
    then
        exit 1
    fi
}

# Read the config file line by line and pass them to other functions
function parse_config_file()
{
    if [ $# -ne 1 ] 
    then
        printf "Usage: parse_line config_file_path\n"
        return 1
    fi

    config_file_path=$1

    line_number=1
    while IFS="" read -r line || [ -n "$line" ] 
    do
        parse_line "$line" $line_number
        line_number=$((line_number + 1))
    done < $config_file_path
}
