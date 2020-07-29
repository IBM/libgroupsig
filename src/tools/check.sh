#!/bin/bash
function results () {
echo "$1 $2 time: ${3}s errors: $4/$5"
}

getTime () {
echo $(date +%s.%N)
return 0
}

time_delta () {
local startTime=$1
local endTime=$2
local elapsedTime=$(echo "$endTime" - "$startTime" | bc -l)
echo $elapsedTime
return 0
}

accumulate () {
local accum=$(echo "$1" + "$2" | bc -l)
echo $accum
return 0
}

test_sign () {
	local scheme=$1
	local i=$2
	./sign $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" msg "$scheme/mem/${i}.key" $scheme/grp/grp.key
	
	if [ $? != 0 ]; then
		((signError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_sign_msg${i}.sig" 
		cp msg "errors/$scheme/${rndstr}_sign_msg"
		cp "$scheme/mem/${i}.key" "errors/$scheme/mem/${rndstr}_sign_${i}.key" 
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_sign_grp.key"
	fi
}

test_verify () {
	local scheme=$1
	local i=$2
	./verify $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" msg $scheme/grp/grp.key > test_$i.out
	
	if [ $? != 0 ]; then
		((verifyError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_verify_msg${i}.sig" 
		cp msg "errors/$scheme/${rndstr}_verify_msg"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_verify_grp.key"
	fi
	cat test_$i.out | grep 'WRONG signature' &> /dev/null
	if [ $? == 0 ]; then
		((wrongSignature += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/kty04/${rndstr}_wrongsig_msg${i}.sig" 
		cp msg "errors/kty04/${rndstr}_wrongsig_msg"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_wrongsig_grp.key"
	fi
	rm -f test_$i.out
}

test_claim () {
	local scheme=$1
	local i=$2
	./claim $scheme $FILEFORMAT "$scheme/mem/${i}.key" $scheme/grp/grp.key "sigs/$scheme/msg${i}.pro" "sigs/$scheme/msg${i}.sig"
	
	if [ $? != 0 ]; then
		((claimError += 1))
		cp "$scheme/mem/${i}.key" "errors/$scheme/mem/${rndstr}_claim_${i}.key" 
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_claim_grp.key"
		cp "sigs/$scheme/msg${i}.pro" "errors/$scheme/${rndstr}_claim_msg${i}.pro" 
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_claim_msg${i}.sig"
	fi
}

test_claim_verify () {
	local scheme=$1
	local i=$2
	./claim_verify $scheme $FILEFORMAT "sigs/$scheme/msg${i}.pro" $scheme/grp/grp.key "sigs/$scheme/msg${i}.sig" > test_$i.out
	
	if [ $? != 0 ]; then
		((claimverError += 1))
		cp "sigs/$scheme/msg${i}.pro" "errors/$scheme/${rndstr}_claimver_msg${i}.pro" 
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_claimver_grp.key"
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_claimver_msg${i}.sig"
	fi

	cat test_$i.out | grep 'WRONG proof' &> /dev/null
	if [ $? == 0 ]; then
		((wrongClaim += 1))
		cp "sigs/$scheme/msg${i}.pro" "errors/$scheme/${rndstr}_wrongproof_msg${i}.pro" 
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_wrongproof_grp.key"
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_wrongproof_msg${i}.sig"
	fi
}

test_member_trace () {
	local scheme=$1
	local i=$2
	./trace $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/crl $scheme/mgr/mgr.key $scheme/mgr/gml > test_$i.out
	if [ $? != 0 ]; then
		((traceMemberError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_tracegood_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_tracegood_grp.key"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_tracegood_crl"
		cp $scheme/mgr/mgr.key "errors/$scheme/${rndstr}_tracegood_mgr.key"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_tracegood_gml"
	fi
	cat test_$i.out | grep 'REVOKED signer' &> /dev/null
	if [ $? == 0 ]; then
		((wrongMemberTrace += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/kty04/${rndstr}_wronggood_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_wronggood_grp.key"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_wronggood_crl"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_wronggood_gml"
	fi
	rm -f test_$i.out	
}

test_revoke_trace () {
	local scheme=$1
	local i=$2
	./trace $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/crl $scheme/mgr/mgr.key $scheme/mgr/gml > test_$i.out
	if [ $? != 0 ]; then
		((traceRevokeError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_tracerevoked_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_tracerevoked_grp.key"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_tracerevoked_crl"
		cp $scheme/mgr/mgr.key "errors/$scheme/${rndstr}_tracerevoked_mgr.key"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_tracerevoked_gml"
	fi
	cat test_$i.out | grep 'VALID signer' &> /dev/null
	if [ $? == 0 ]; then
		((wrongRevokeTrace += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_wrongrevoked_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_wrongrevoked_grp.key"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_wrongrevoked_crl"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_wrongrevoked_gml"
	fi

	rm -f test_$i.out	
}

# Do not run in parallel
test_revoke () {
	local scheme=$1
	local i=$2
	./revoke $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/mgr.key $scheme/mgr/gml $scheme/mgr/crl
	if [ $? != 0 ]; then
		((revokeError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_revoke_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_revoke_grp.key"
		cp $scheme/mgr/mgr.key "errors/$scheme/${rndstr}_revoke_mgr.key"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_revoke_gml"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_revoke_crl"
	fi
}


test_scheme () {
local scheme=$1
local count=$2
local cpus=$3
#local count2=$((count*2))
echo "----- Testing $scheme -----"

signError=0
verifyError=0
claimError=0
claimverError=0
traceError=0
revokeError=0
traceMemberError=0
traceRevokeError=0
wrongSignature=0
wrongClaim=0
wrongMemberTrace=0
wrongRevokeTrace=0
 
local createTime=0
local joinTime=0
local signingTime=0
local verifyTime=0
local claimTime=0
local claimVerifyTime=0
local traceMemberTime=0
local revokeTime=0
local traceRevokedTime=0
mkdir -p sigs/$scheme

st=$(getTime)
./group_create $scheme $FILEFORMAT -d $scheme -M mgr -g grp -m mem -b 256 2>&1 > /dev/null
createTime=$(accumulate $createTime  $(time_delta $st $(getTime)))
if [ $? != 0 ]; then 
	echo "Error creating group."
	exit 1
fi
echo "$scheme creation time: ${createTime}s"


st=$(getTime)
./join $scheme $FILEFORMAT $scheme/grp/grp.key $scheme/mgr/mgr.key $scheme/mgr/gml $scheme/mem $count
joinTime=$(accumulate $joinTime  $(time_delta $st $(getTime)))
if [ $? != 0 ]; then
	echo "Error creating group members."
	exit 1
fi
echo "$scheme join time: ${joinTime}s ($count members)"


touch $scheme/mgr/crl

proccount=0
for i in `seq 0 $(($count - 1))`; do
	st=$(getTime)
	test_sign $scheme $i &
	((proccount += 1))
	if [ $proccount -ge $cpus ] ; then
		wait
		proccount=0
	fi
	signingTime=$(accumulate $signingTime  $(time_delta $st $(getTime)))
    if [ $i -gt 0 ] ; then
    	tput cuu 1 && tput el
	fi
	results $scheme "sign" $signingTime $signError $i
done
tput cuu 1 && tput el
results $scheme "sign" $signingTime $signError $count


for i in `seq 0 $(($count - 1))`; do
	st=$(getTime)
	#verify
	test_verify $scheme $i &
	((proccount += 1))
	if [ $proccount -ge $cpus ] ; then
		wait
		proccount=0
	fi
	verifyTime=$(accumulate $verifyTime  $(time_delta $st $(getTime)))
    if [ $i -gt 0 ] ; then
    	tput cuu 1 && tput el
	fi
	results $scheme "verify" $verifyTime $verifyError $i
done
tput cuu 1 && tput el
results $scheme "verify" $verifyTime $verifyError $count


    if [ "$scheme" != "bbs04" ] ; then
    	for i in `seq 0 $(($count - 1))`; do
			st=$(getTime)
			#claim
			test_claim $scheme $i &
			((proccount += 1))
			if [ $proccount -ge $cpus ] ; then
				wait
				proccount=0
			fi
			claimTime=$(accumulate $claimTime  $(time_delta $st $(getTime)))
		    if [ $i -gt 0 ] ; then
		    	tput cuu 1 && tput el
			fi
			results $scheme "claim" $claimTime $claimError $i
		done
		tput cuu 1 && tput el
		results $scheme "claim" $claimTime $claimError $count
		
		
	
    	for i in `seq 0 $(($count - 1))`; do
			st=$(getTime)
			#claim verify
			test_claim_verify $scheme $i &
			((proccount += 1))
			if [ $proccount -ge $cpus ] ; then
				wait
				proccount=0
			fi
			claimVerifyTime=$(accumulate $claimVerifyTime  $(time_delta $st $(getTime)))
		    if [ $i -gt 0 ] ; then
		    	tput cuu 1 && tput el
			fi
			results $scheme "claim_verify" $claimVerifyTime $claimverError $i
		done
		tput cuu 1 && tput el
		results $scheme "claim_verify" $claimVerifyTime $claimverError $count
		
    fi

	for i in `seq 0 $(($count - 1))`; do
		st=$(getTime)
		#trace
		test_member_trace $scheme $i &
		((proccount += 1))
		if [ $proccount -ge $cpus ] ; then
			wait
			proccount=0
		fi
		traceMemberTime=$(accumulate $traceMemberTime  $(time_delta $st $(getTime)))
	    if [ $i -gt 0 ] ; then
	    	tput cuu 1 && tput el
		fi
		results $scheme "trace(members)" $traceMemberTime $traceError $i
	done
	tput cuu 1 && tput el
	results $scheme "trace(members)" $traceMemberTime $traceError $count

	for i in `seq 0 $(($count - 1))`; do
		st=$(getTime)
		#revoke
		test_revoke $scheme $i 
		revokeTime=$(accumulate $revokeTime  $(time_delta $st $(getTime)))
	    if [ $i -gt 0 ] ; then
	    	tput cuu 1 && tput el
		fi
		results $scheme "revoke" $revokeTime $revokeError $i
	done
	tput cuu 1 && tput el
	results $scheme "revoke" $revokeTime $revokeError $count

	for i in `seq 0 $(($count - 1))`; do
		st=$(getTime)
		#revoked trace
		test_revoke_trace $scheme $i &
		((proccount += 1))
		if [ $proccount -ge $cpus ] ; then
			wait
			proccount=0
		fi
		traceRevokedTime=$(accumulate $traceRevokedTime  $(time_delta $st $(getTime)))
	    if [ $i -gt 0 ] ; then
	    	tput cuu 1 && tput el
		fi
		results $scheme "trace(revoked)" $traceRevokedTime $traceError $i
	done
	tput cuu 1 && tput el
	results $scheme "trace(revoked)" $traceRevokedTime $traceError $count

echo "Wrong $scheme signatures: ${wrongSignature}/$count"
echo "Wrong $scheme claims: ${wrongClaim}/$count"
echo "Wrong $scheme traces(members): ${wrongMemberTrace}/$count"
echo "Wrong $scheme traces(revoked): ${wrongRevokeTrace}/$count"

}

rm -Rf sigs kty04 bbs04 cpy06
# FILEFORMAT can be "bin" or "b64" for binary and base64, respectively
FILEFORMAT="b64"

# https://gist.github.com/earthgecko/3089509 ghost comment
rndmsg=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1`
rndstr=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1`
rndstr=${rndstr:0:6}
echo "rndstr: $rndstr"
echo "rndmsg: $rndmsg"

echo -n $rndmsg > msg
mkdir sigs
mkdir -p errors/kty04 errors/bbs04 errors/cpy06

if [ -z $2 ] ; then
cpus=1
else
cpus=$2 #$(grep -c ^processor /proc/cpuinfo)
fi

if [ $cpus -gt 1 ] ; then
	echo
	echo "WARNING: For timing data, use only one cpu"
fi
count=$1
test_scheme "kty04" $count $cpus
test_scheme "bbs04" $count $cpus
test_scheme "cpy06" $count $cpus

