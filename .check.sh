#!/bin/sh 
info=`pocsuite -r pocs -u 127.0.0.1`
text="register"
eval 'pocsuite -r pocs -f target.txt'
result=$(echo $info | grep "${text}")
if [ "$result" != "" ]
then
	echo "failed"
	exit 1
else
	echo "success"
	exit 0
fi
