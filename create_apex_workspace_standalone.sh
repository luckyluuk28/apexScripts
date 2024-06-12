#!/bin/bash

set -e

parameter_allowed_pattern='^[a-zA-Z0-9.,:_-]+$'
parameter_allowed_error="may only contain alphanumeric characters, dots, comma's, colons, underscores and hyphen." # "Error: $option" get's put in front of the error message
password_not_allowed_pattern="[ ;']"
password_not_allowed_error="may not contain spaces, semicolons, or single quotes." # "Error: $option" get's put in front of the error message

verbose="N"

# Predefined variables
oracle_user="oracle"

no_password_sudoer=$(sudo -n -l 2>&1 | grep -E -c "(NOPASSWD: ALL|NOPASSWD:.*)")

# User input variables
workspace_name=""
oracle_password=""
workspace_schema=""
schema_password=""
sysdba_username="sys"
sysdba_password="free"
pluggable_database="freepdb1"
admin_username="ADMIN"
admin_password="oracle"
password_length=12

# Boolean User input variables
ignore_password_strength="N"
generate_random_password="N"
verbose="N"

# Usage function to display help
usage() {
    echo -e "Usage: $0 workspace-name [option]...
Use '$0 -h' for more information."

    [ "$1" = "0" ] && exit 0 || exit 1
}

help() {
    echo -e "Install APEX Environment
This script installs an APEX environment.

Usage: $0 workspace-name [option]...

Options:
-opw --oracle-password          The password for the oracle user.
-sdu --sysdba-username          The username for the sysdba user. (default: sys)
-sdp --sysdba-password          The password for the sysdba user. (default: free)
-wss --workspace-schema         The workspace schema.
-spw --schema-password          The password for the workspace schema.
-pdb --pluggable-database       The pluggable database. (default: freepdb1)
-aun --admin-username           The admin username. (default: ADMIN)
-apw --admin-password           The admin password. (default: oracle)
-pwl --password-length          The length of the generated password. (default: 12)
-grp --generate-random-password Generate a random password for the schema. (default: N)
-ips --ignore-password-strength Ignore password strength requirements. (default: N)
-v   --verbose                  Verbose output. (default: N)
-h   --help                     Displays this help message.
"
    exit 0
}

# Function to validate flagged boolean (boolean given as a flag/option. ex: -swc)
getBoolean() {
    local option="$1"
    local value="$2"
    local value_upper
    value_upper=$(echo "$value" | tr '[:lower:]' '[:upper:]')


    if [[ -z "$value" || "$value" == -* ]]; then
        echo "Y"
    else 
        case "$value_upper" in
            Y|YES|TRUE|1)
                echo "Y"
                ;;
            N|NO|FALSE|0)
                echo "N"
                ;;
            *)
                echo "Invalid option: $value for argument: $option" >&2
                usage 1
                ;;
        esac
    fi
}

# Function to validate flagged parameter (parameter given as a flag/option. ex: -app oracle)
getParameter() {
    local option="$1"
    local value="$2"

    if [[ ! $value =~ $parameter_allowed_pattern ]]; then
        echo "Error: $option $parameter_allowed_error" >&2
        exit 1
    fi

    echo "$value"
}

# Function to validate flagged password (password given as a flag/option. ex: -spw oracle)
getPassword() {
    local option="$1"
    local value="$2"

    # Check if password could contain sql injection
    if [[ $value =~ $password_not_allowed_pattern ]]; then
        echo "Error: $option $password_not_allowed_error" >&2
        exit 1
    fi

    echo "$value"
}

parseOutput() {
    local exit_status=0
    
    while IFS= read -r line; do
        case "$line" in
            "Password for "*)
                echo "$line"
                ;;
            "SQLPROMPT: "*)
                echo "${line:11}"
                ;;
            *"Error"*|*"ORA-"*)
                echo "$line" >&2
                exit_status=1
                ;;
            *)
                if [[ "$verbose" == "Y" || "$exit_status" -eq 1 ]]; then
                    echo "$line"
                fi
                ;;
        esac
    done

    if [[ "$exit_status" -eq 1 ]]; then
        exit 1
    fi
}

runScript() {
    local script="$1"
    local command="$2"
    local no_password_sudoer="$3"
    local oracle_user="$4"
    local oracle_password="$5"

    if [[ -n "$oracle_password" ]]; then
        echo -e "$oracle_password\n$script" | su - "$oracle_user" -c "$command"
    elif [[ $no_password_sudoer -eq 1 ]]; then
        echo -e "$script" | sudo su - "$oracle_user" -c "$command"
    else 
        echo "No Oracle password provided. You will need to fill it in manually." 
        echo -e "$script" | su - "$oracle_user" -c "$command"
    fi 
}

validatePassword() {
    local password="$1"

    if [[ -z "$password" ]]; then
        return 1
    fi

    if [[ $password =~ $password_not_allowed_pattern ]]; then
        echo "Error: Password $password_not_allowed_error" >&2
        return 1
    fi
    
    if [[ "$ignore_password_strength" == "Y" ]]; then
        return 0
    fi

    if [[ "${#password}" -lt $password_length ]]; then
        echo "Error: Password must be at least $password_length characters long." >&2
        return 1
    fi

    if ! [[ "$password" =~ [[:upper:]] ]]; then
        echo "Error: Password must contain at least one uppercase letter." >&2
        return 1
    fi

    if ! [[ "$password" =~ [[:lower:]] ]]; then
        echo "Error: Password must contain at least one lowercase letter." >&2
        return 1
    fi

    if ! [[ "$password" =~ [[:digit:]] ]]; then
        echo "Error: Password must contain at least one number." >&2
        return 1
    fi

    # if ! [[ "$password" =~ [[:punct:]] ]]; then
    #     echo "Error: Password must contain at least one special character." >&2
    #     return 1
    # fi

    return 0
}

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    help
fi

if [[ $# -lt 1 ]]; then
    usage 1
fi

workspace_name=$(getParameter "workspace-name" "$1")

shift 1 # Ensure this stays the same as the required argument count

if [[ -z "$workspace_name" ]]; then
    echo "Error: Workspace name is required." >&2
    usage 1
fi

# Parse optional arguments
while [[ $# -gt 0 ]]; do
    option="$1"
    option_lower="$(echo "$option" | tr '[:upper:]' '[:lower:]')"
    value="$2"

    case "$option_lower" in
        -opw|--oracle-password)
            oracle_password=$(getPassword "$option" "$value")
            ;;
        -sdu|--sysdba-username)
            sysdba_username=$(getParameter "$option" "$value")
            ;;
        -sdp|--sysdba-password) 
            sysdba_password=$(getPassword "$option" "$value")
            ;;
        -wss|--workspace-schema)
            workspace_schema=$(getParameter "$option" "$value")
            ;;
        -spw|--schema-password)
            schema_password=$(getPassword "$option" "$value")
            ;;
        -pdb|--pluggable-database)
            pluggable_database=$(getParameter "$option" "$value")
            ;;
        -aun|--admin-username)
            admin_username=$(getParameter "$option" "$value")
            ;;
        -apw|--admin-password)
            admin_password=$(getPassword "$option" "$value")
            ;;
        -pwl|--password-length)
            if [[ ! "$value" =~ ^[0-9]+$ ]]; then
                echo "Error: Invalid password length \"$value\". Must be a number." >&2
                usage 1
            fi
            password_length="$value"
            ;;
        -grp|--generate-random-password)
            generate_random_password=$(getBoolean "$option" "$value")
            ;;
        -ips|--ignore-password-strength)
            ignore_password_strength=$(getBoolean "$option" "$value")
            ;;
        -v|--verbose)
            verbose=$(getBoolean "$option" "$value")
            ;;
        *)
            echo "Unknown option: $option" >&2
            usage 1
            ;;
    esac
    if [[ -n "$value" && "$value" != -* ]]; then
        shift 2
    else
        shift 1
    fi
done

# Fill in missing values
if [[ -z "$workspace_schema" ]]; then
    workspace_schema="$workspace_name"
fi

# Get the schema password if not provided
if [[ -z "$schema_password" && "$generate_random_password" == "Y" ]]; then
    schema_password=$(openssl rand -base64 "$password_length" | tr -d '/+=')
    echo "Generated random schema password: $schema_password for $workspace_schema"
elif [[ -z "$schema_password" ]]; then
    echo "No Schema password provided. Please provide a password." >&2
    
    while ! validatePassword "$schema_password"; do
        read -r -s -p "Enter Schema password: " schema_password
        echo -e "\n"
    done
elif [[ -n "$schema_password" ]]; then
    if ! validatePassword "$schema_password"; then
        echo "If you want to ignore password strength requirements use the -ips or --ignore-password-strength flag." >&2
        exit 1
    fi
else
    echo "Error: Schema password not provided." >&2
    usage 1
fi

# Create the SQL script, run it as oracle user to create the workspace and user (schema) if they dont exist.
sql_script=$(cat << EOF
connect $sysdba_username/$sysdba_password as sysdba

whenever sqlerror exit sql.sqlcode rollback

alter session set container = $pluggable_database;
set feedback off serveroutput on

prompt SQLPROMPT: Creating schema $workspace_schema...

declare
  l_user_exists number;
begin
  -- Check if the user already exists
  select count(*)
  into l_user_exists
  from dba_users
  where username = upper('$workspace_schema');

  -- If user does not exist, create the user and grant privileges
  if l_user_exists = 0 then
    execute immediate 'CREATE USER $workspace_schema IDENTIFIED BY "$schema_password" 
    DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS';
    
    -- Grant privileges to the user
    execute immediate 'GRANT EXECUTE ON sys.dbms_crypto TO $workspace_schema';
    execute immediate 'GRANT EXECUTE ON APEX_UTIL TO $workspace_schema';
    execute immediate 'GRANT CREATE SESSION, CREATE CLUSTER, CREATE DIMENSION, CREATE INDEXTYPE,
                      CREATE JOB, CREATE MATERIALIZED VIEW, CREATE OPERATOR, CREATE PROCEDURE,
                      CREATE SEQUENCE, CREATE SYNONYM, CREATE TABLE, CREATE TRIGGER, CREATE TYPE, 
                      CREATE VIEW, CREATE MLE TO $workspace_schema';
  else
    dbms_output.put_line('SQLPROMPT: Schema already exists. Skipping Creation...');
  end if;
end;
/

prompt SQLPROMPT: Creating workspace $workspace_name...

declare
    l_workspace_exists number; 
begin
    select count(*)
    into l_workspace_exists
    from apex_workspaces
    where workspace = upper('$workspace_name');

    if l_workspace_exists = 0 then 
        apex_instance_admin.add_workspace (
            p_workspace         => '$workspace_name',
            p_primary_schema    => '$workspace_schema'
        );

        apex_util.set_workspace (
            p_workspace => '$workspace_name'
        ); 

        apex_util.create_user (
            p_user_name                     => '$admin_username',
            p_web_password                  => '$admin_password',
            p_developer_privs               => 'ADMIN:CREATE:DATA_LOADER:EDIT:HELP:MONITOR:SQL',
            p_change_password_on_first_use  => '$([ "$admin_password" == "oracle" ] && echo "Y" || echo "N")'
        );

        dbms_output.put_line('$( [ "$admin_username" == "ADMIN" ] && echo "SQLPROMPT: Default admin username \"$admin_username\" used." || echo "" )');
        dbms_output.put_line('$( [ "$admin_password" == "oracle" ] && echo "SQLPROMPT: Default admin password \"$admin_password\" used." || echo "" )');
    else
        dbms_output.put_line('SQLPROMPT: Workspace already exists. Skipping Creation...');
    end if;

    commit;
end;
/
EOF
)

runScript "$sql_script" "sql /nolog" "$no_password_sudoer" "$oracle_user" "$oracle_password" | parseOutput

exit 0
