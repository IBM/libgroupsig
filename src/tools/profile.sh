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
	local iter=$3
	./sign $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" msg "$scheme/mem/${i}.key" $scheme/grp/grp.key $iter
	
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
	local iter=$3
	./verify $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" msg $scheme/grp/grp.key $iter > test_$i.out
	
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
	local iter=$3
	./claim $scheme $FILEFORMAT "$scheme/mem/${i}.key" $scheme/grp/grp.key "sigs/$scheme/msg${i}.pro" "sigs/$scheme/msg${i}.sig" $iter
	
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
	local iter=$3
	
	./claim_verify $scheme $FILEFORMAT "sigs/$scheme/msg${i}.pro" $scheme/grp/grp.key "sigs/$scheme/msg${i}.sig" $iter > test_$i.out

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
	local iter=$3

	./trace $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/crl $scheme/mgr/mgr.key $scheme/mgr/gml $iter > test_$i.out
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
	local iter=$3

	./trace $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/crl $scheme/mgr/mgr.key $scheme/mgr/gml $iter > test_$i.out
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
	local iter=$3

	./revoke $scheme $FILEFORMAT "sigs/$scheme/msg${i}.sig" $scheme/grp/grp.key $scheme/mgr/mgr.key $scheme/mgr/gml $scheme/mgr/crl $iter
	if [ $? != 0 ]; then
		((revokeError += 1))
		cp "sigs/$scheme/msg${i}.sig" "errors/$scheme/${rndstr}_revoke_msg${i}.sig"
		cp $scheme/grp/grp.key "errors/$scheme/${rndstr}_revoke_grp.key"
		cp $scheme/mgr/mgr.key "errors/$scheme/${rndstr}_revoke_mgr.key"
		cp $scheme/mgr/gml "errors/$scheme/${rndstr}_revoke_gml"
		cp $scheme/mgr/crl "errors/$scheme/${rndstr}_revoke_crl"
	fi
}

calculate_average_time () {
	file=$1
	totalwt=0
	totalcpu=0
	totalcycles=0
	while read -r l; do
		wt=$(echo "$l" |cut -d $'\t' -f 3)
		cput=$(echo "$l" |cut -d $'\t' -f 6)
		cycles=$(echo "$l" |cut -d $'\t' -f 9)
		totalwt=$(echo "$wt + $totalwt" | bc -l)
		totalcpu=$(echo "$cput + $totalcpu" | bc -l)
		totalcycles=$(echo "$cycles + $totalcycles" | bc -l)
	done < $file 
	echo -n Average Time: 
	echo -n $(echo "scale=7; $totalwt/$count" | bc -l)
	echo -n $'\t'
	echo $(echo "scale=7; $totalcpu/$count" | bc -l)
	echo -n $'\t'
	echo $(echo "scale=0; $totalcycles/$count" | bc -l)
}

test_scheme () {
local scheme=$1
if [ -z $2 ] ; then
	echo "No count given. Profiling with 10 runs." 1>&2
	local count=10
else
	local count=$2
fi
echo "----- Profiling $scheme -----"
mkdir -p sigs/$scheme

echo "Creating group"
./group_create $scheme $FILEFORMAT -d $scheme -M mgr -g grp -m mem -b 384 -n 1 2>&1 > /dev/null
echo $(calculate_average_time group_create.prf)

echo "Joining members"
./join $scheme $FILEFORMAT $scheme/grp/grp.key $scheme/mgr/mgr.key $scheme/mgr/gml $scheme/mem $count
echo $(calculate_average_time join.prf)

touch $scheme/mgr/crl

echo "Profiling sign"
test_sign $scheme 0 $count
echo $(calculate_average_time sign.prf)

echo "Signing $((count)) messages to do revocation later."
for i in `seq 0 $(($count - 1))` ; do
	test_sign $scheme $i 1
done

echo "Profiling verify"
test_verify $scheme 0 $count
echo $(calculate_average_time verify.prf)

    if [ "$scheme" != "bbs04" ] ; then
    	echo "Profiling claim"
		test_claim $scheme 0 $count
		echo $(calculate_average_time claim.prf)
    	echo "Profiling claim verify"
		test_claim_verify $scheme 0 $count
		echo $(calculate_average_time claim_verify.prf)
    fi
echo "Profiling trace"
test_member_trace $scheme 0 $count
echo $(calculate_average_time trace.prf)
rm trace.prf
echo "Profiling revoke"
test_revoke $scheme 0 $count
echo -n "Open "; echo $(calculate_average_time open.prf)
echo -n "Reveal "; echo $(calculate_average_time reveal.prf)
echo "Revoking all members"
for i in `seq 0 $(($count - 1))` ; do
	test_revoke $scheme $i 1
done
echo "Profiling trace again"
test_revoke_trace $scheme 0 $count
echo $(calculate_average_time trace.prf)




}

rm -Rf sigs kty04 bbs04 cpy06 *.prf
# FILEFORMAT can be "bin" or "b64" for binary and base64, respectively
FILEFORMAT="bin"

# https://gist.github.com/earthgecko/3089509 ghost comment
rndmsg=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1`
rndstr=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1`
rndstr=${rndstr:0:6}
echo "rndstr: $rndstr"
echo "rndmsg: $rndmsg"

echo -n $rndmsg > msg
mkdir sigs
mkdir -p errors/kty04 errors/bbs04 errors/cpy06

count=$1
test_scheme "kty04" $count
mv *.prf "kty04/"
test_scheme "bbs04" $count
mv *.prf "bbs04/"
test_scheme "cpy06" $count
mv *.prf "cpy06/"

