#!/bin/sh
echo "---------exp check----------"
info_exp=`pocsuite -r exps -u 127.0.0.1 `
text_exp="register"
eval 'pocsuite -r pocs -f target.txt --thread 40'
result_exp=$(echo $info_exp | grep "${text_exp}")
if [ "$result_exp" != "" ]
then
	echo "failed"
	exit 1
else
	echo "success"
	exit 0
fi
