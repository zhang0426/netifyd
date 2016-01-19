#!/bin/bash

my_dir=$(dirname "$0")
src_dir=$(realpath "$my_dir/..")

generate_object_type()
{
	i=1

	cat << EOF
// Auto-generated JSON object types.
// WARNING: All modifications will be LOST!

EOF

	if [ "$1" == "c" ]; then
		cat << EOF
#ifndef _ND_JSON_OBJECT_TYPE_H
#define _ND_JSON_OBJECT_TYPE_H

enum ndJsonObjectType
{
    ndJSON_OBJ_TYPE_NULL = 0,
EOF
	fi

	while read token; do
		t=$(echo $token | tr '[:lower:]' '[:upper:]')
		if [ "$1" == "c" ]; then
			printf "    ndJSON_OBJ_TYPE_%s = %d,\n" $t $i
		elif [ "$1" == "php" ]; then
			printf "define('NS_JSON_OBJ_TYPE_%s', %d);\n" $t $i
		fi
		i=$[ $i + 1 ]
	done < $src_dir/include/nd-json-object-type.txt.in

	if [ "$1" == "c" ]; then
		cat << EOF
    ndJSON_OBJ_TYPE_MAX = $i
};

#endif // _ND_JSON_OBJECT_TYPE_H
EOF
	fi
}

generate_result_code()
{
	i=1

	cat << EOF
// Auto-generated JSON result codes 
// WARNING: All modifications will be LOST!

EOF

	if [ "$1" == "c" ]; then
		cat << EOF
#ifndef _ND_JSON_RESULT_CODE_H
#define _ND_JSON_RESULT_CODE_H

enum ndJsonObjectResultCode
{
    ndJSON_RES_NULL = 0,
EOF
	fi

	while read token; do
		t=$(echo $token | tr '[:lower:]' '[:upper:]')
		if [ "$1" == "c" ]; then
			printf "    ndJSON_RES_%s = %d,\n" $t $i
		elif [ "$1" == "php" ]; then
			printf "define('NS_JSON_RES_%s', %d);\n" $t $i
		fi
		i=$[ $i + 1 ]
	done < $src_dir/include/nd-json-result-code.txt.in

	if [ "$1" == "c" ]; then
		cat << EOF
    ndJSON_RES_MAX = $i
};

#endif // _ND_JSON_RESULT_CODE_H
EOF
	fi
}

case "$1" in
c-object-type)
	generate_object_type c
	;;
php-object-type)
	generate_object_type php
	;;
c-result-code)
	generate_result_code c
	;;
php-result-code)
	generate_result_code php
	;;
*)
	exit 1
esac

exit 0

