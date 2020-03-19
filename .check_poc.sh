#!/bin/sh
echo "---------poc check----------"
poc_command=`pocsuite -r pocs -u 107.182.25.94:7001 `
error_message="register"
eval 'pocsuite -r pocs -f target.txt --thread 40'
result_poc=$(echo $poc_command | grep "${error_message}")
if [ "$result_poc" != "" ]
then
	echo "failed"
	exit 1
else
	echo "success"
	exit 0
fi
