#!/bin/sh
echo "---------exp check----------"
exp_command=`pocsuite -r exps -u 127.0.0.1 `
error_message="register"
eval 'pocsuite -r exps -f target.txt --thread 40'
result_exp=$(echo $exp_command | grep "${error_message}")
if [ "$result_exp" != "" ]
then
	echo "failed"
	exit 1
else
	echo "success"
	exit 0
fi
