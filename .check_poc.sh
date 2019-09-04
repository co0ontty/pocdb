#!/bin/sh 
info_poc=`pocsuite -r pocs -u 127.0.0.1 --thread 20`
text_poc="register"
eval 'pocsuite -r pocs -f target.txt'
result_poc=$(echo $info_poc | grep "${text_poc}")
if [ "$result_poc" != "" ]
then
	echo "failed"
	exit 1
else
	echo "success"
	exit 0
fi
