#!/bin/bash

#
# Script for quick addition of new group signature schemes to the
# libgroupsig library.
#
# NOTE: Unmaintained! This probably does not work!
#  

E_OK=0;
E_EINVAL=87;
E_UNSUPPORTED=88;

#rootdir=@GSROOTDIR@
cd ..
rootdir=`pwd`
cd tools

# Basic usage
if [[ $# -lt 1 || $# -gt 2 ]]; then
	echo "Usage: `basename $0` <command> <arg>";
	echo "Type `basename $0` -h or `basename $0` --help for help.";
	exit $E_EINVAL;
fi

# Supported actions help
if [[ $1 == "-h" || $1 == "--help" ]]; then
	echo -en "Supported commands:\n";
	echo -en "\t* addscheme <scheme name>\n";
	echo -en "\t* addcrl <crl type name>\n";
	echo -en "\t* addgml <gml type name>\n";
	echo -en "\t* addid <ID type name>\n";
	exit $E_OK;
fi

scheme=`echo $2 | tr '[A-Z]' '[a-z]'`
SCHEME=`echo $2 | tr '[a-z]' '[A-Z]'`

case $1 in

	addscheme )

		echo "Running addscheme on '$2' ..."

		# Copy main header file
		echo "Creating main header file in $rootdir/include/${scheme}.h"
		cp $rootdir/.templates/include/newscheme.h $rootdir/include/${scheme}.h

		# Replace occurences of %%newscheme%% and %%NEWSCHEME%%
		sed 's/%%NEWSCHEME%%/'"$SCHEME"'/g' $rootdir/include/${scheme}.h > $rootdir/include/${scheme}.tmp.h
		sed 's/%%newscheme%%/'"$scheme"'/g' $rootdir/include/${scheme}.tmp.h > $rootdir/include/${scheme}.h
		rm $rootdir/include/${scheme}.tmp.h

		# Copy scheme files
		echo "Creating scheme files in $rootdir/groupsig/${scheme}/"
		mkdir $rootdir/groupsig/$scheme
		cp $rootdir/.templates/groupsig/newscheme/* $rootdir/groupsig/$scheme
		for file in `ls $rootdir/groupsig/$scheme`; do
			sed 's/%%NEWSCHEME%%/'"$SCHEME"'/g' $rootdir/groupsig/$scheme/${file} > $rootdir/groupsig/$scheme/${file}.tmp
			sed 's/%%newscheme%%/'"$scheme"'/g' $rootdir/groupsig/$scheme/${file}.tmp > $rootdir/groupsig/$scheme/${file}
			rm $rootdir/groupsig/$scheme/${file}.tmp		
		done

		cd $rootdir/include
		echo "Updating $rootdir/include/registered_groupsigs.h"
		sed "s/#include \"groupsig.h\"$/#include \"groupsig.h\"\n#include \"${scheme}.h\"/" registered_groupsigs.h > registered_groupsigs.h.tmp
		mv registered_groupsigs.h.tmp registered_groupsigs.h

		echo "Updating $rootdir/include/grp_key_handles.h"
		sed "s/#include \"grp_key.h\"$/#include \"grp_key.h\"\n#include \"groupsig\/${scheme}\/grp_key.h\"/" grp_key_handles.h > grp_key_handles.h.tmp
		mv grp_key_handles.h.tmp grp_key_handles.h
		num=$((`grep "#define GROUPSIG_GRP_KEY_HANDLES_N" grp_key_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GROUPSIG_GRP_KEY_HANDLES_N .*$/#define GROUPSIG_GRP_KEY_HANDLES_N $num/" grp_key_handles.h > grp_key_handles.h.tmp	
		mv grp_key_handles.h.tmp grp_key_handles.h
		sed "s/\(const grp_key_handle_t \*GROUPSIG_GRP_KEY_HANDLES\[GROUPSIG_GRP_KEY_HANDLES_N\] = {\)/\1 \n  \&${scheme}_grp_key_handle,/" grp_key_handles.h > grp_key_handles.h.tmp
		mv grp_key_handles.h.tmp grp_key_handles.h

		echo "Updating $rootdir/include/mem_key_handles.h"
		sed "s/#include \"mem_key.h\"$/#include \"mem_key.h\"\n#include \"groupsig\/${scheme}\/mem_key.h\"/" mem_key_handles.h > mem_key_handles.h.tmp
		mv mem_key_handles.h.tmp mem_key_handles.h
		num=$((`grep "#define GROUPSIG_MEM_KEY_HANDLES_N" mem_key_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GROUPSIG_MEM_KEY_HANDLES_N .*$/#define GROUPSIG_MEM_KEY_HANDLES_N $num/" mem_key_handles.h > mem_key_handles.h.tmp	
		mv mem_key_handles.h.tmp mem_key_handles.h
		sed "s/\(const mem_key_handle_t \*GROUPSIG_MEM_KEY_HANDLES\[GROUPSIG_MEM_KEY_HANDLES_N\] = {\)/\1 \n  \&${scheme}_mem_key_handle,/" mem_key_handles.h > mem_key_handles.h.tmp
		mv mem_key_handles.h.tmp mem_key_handles.h

		echo "Updating $rootdir/include/mgr_key_handles.h"
		sed "s/#include \"mgr_key.h\"$/#include \"mgr_key.h\"\n#include \"groupsig\/${scheme}\/mgr_key.h\"/" mgr_key_handles.h > mgr_key_handles.h.tmp
		mv mgr_key_handles.h.tmp mgr_key_handles.h
		num=$((`grep "#define GROUPSIG_MGR_KEY_HANDLES_N" mgr_key_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GROUPSIG_MGR_KEY_HANDLES_N .*$/#define GROUPSIG_MGR_KEY_HANDLES_N $num/" mgr_key_handles.h > mgr_key_handles.h.tmp	
		mv mgr_key_handles.h.tmp mgr_key_handles.h
		sed "s/\(const mgr_key_handle_t \*GROUPSIG_MGR_KEY_HANDLES\[GROUPSIG_MGR_KEY_HANDLES_N\] = {\)/\1 \n  \&${scheme}_mgr_key_handle,/" mgr_key_handles.h > mgr_key_handles.h.tmp
		mv mgr_key_handles.h.tmp mgr_key_handles.h

		echo "Updating $rootdir/include/signature_handles.h"
		sed "s/#include \"signature.h\"$/#include \"signature.h\"\n#include \"groupsig\/${scheme}\/signature.h\"/" signature_handles.h > signature_handles.h.tmp
		mv signature_handles.h.tmp signature_handles.h
		num=$((`grep "#define GROUPSIG_SIGNATURE_HANDLES_N" signature_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GROUPSIG_SIGNATURE_HANDLES_N .*$/#define GROUPSIG_SIGNATURE_HANDLES_N $num/" signature_handles.h > signature_handles.h.tmp	
		mv signature_handles.h.tmp signature_handles.h
		sed "s/\(const groupsig_signature_handle_t \*GROUPSIG_SIGNATURE_HANDLES\[GROUPSIG_SIGNATURE_HANDLES_N\] = {\)/\1 \n  \&${scheme}_signature_handle,/" signature_handles.h > signature_handles.h.tmp
		mv signature_handles.h.tmp signature_handles.h

		echo "Updating $rootdir/include/proof_handles.h"
		sed "s/#include \"proof.h\"$/#include \"proof.h\"\n#include \"groupsig\/${scheme}\/proof.h\"/" proof_handles.h > proof_handles.h.tmp
		mv proof_handles.h.tmp proof_handles.h
		num=$((`grep "#define GROUPSIG_PROOF_HANDLES_N" proof_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GROUPSIG_PROOF_HANDLES_N .*$/#define GROUPSIG_PROOF_HANDLES_N $num/" proof_handles.h > proof_handles.h.tmp	
		mv proof_handles.h.tmp proof_handles.h
		sed "s/\(const groupsig_proof_handle_t \*GROUPSIG_PROOF_HANDLES\[GROUPSIG_PROOF_HANDLES_N\] = {\)/\1 \n  \&${scheme}_proof_handle,/" proof_handles.h > proof_handles.h.tmp
		mv proof_handles.h.tmp proof_handles.h

		echo "Updating $rootdir/include/trapdoor_handles.h"
		sed "s/#include \"trapdoor.h\"$/#include \"trapdoor.h\"\n#include \"groupsig\/${scheme}\/trapdoor.h\"/" trapdoor_handles.h > trapdoor_handles.h.tmp
		mv trapdoor_handles.h.tmp trapdoor_handles.h
		num=$((`grep "#define TRAPDOOR_HANDLES_N" trapdoor_handles.h | cut -d' ' -f3`+1))
		sed "s/#define TRAPDOOR_HANDLES_N .*$/#define TRAPDOOR_HANDLES_N $num/" trapdoor_handles.h > trapdoor_handles.h.tmp	
		mv trapdoor_handles.h.tmp trapdoor_handles.h
		sed "s/\(const trapdoor_handle_t \*TRAPDOOR_HANDLES\[TRAPDOOR_HANDLES_N\] = {\)/\1 \n  \&${scheme}_trapdoor_handle,/" trapdoor_handles.h > trapdoor_handles.h.tmp
		mv trapdoor_handles.h.tmp trapdoor_handles.h

		cd -

		echo "Updating $rootdir/configure.ac"
		cd $rootdir
		sed "s!groupsig/Makefile!groupsig/Makefile\n\t\t groupsig/${scheme}/Makefile!" configure.ac > configure.ac.tmp
		mv configure.ac.tmp configure.ac

		echo "Updating $rootdir/Makefile.am"
		sed 's!$(top_builddir)/sys/libsys.la \\!$(top_builddir)/groupsig/'${scheme}'/lib'${scheme}'.la \\\n\t$(top_builddir)/sys/libsys.la \\!' Makefile.am > Makefile.am.tmp
		mv Makefile.am.tmp Makefile.am

		cd -

		cd $rootdir/groupsig
		echo "Updating $rootdir/groupsig/Makefile.am"
		sed "s/SUBDIRS =/SUBDIRS = ${scheme}/" Makefile.am > Makefile.am.tmp
		mv Makefile.am.tmp Makefile.am
		cd -

		echo "Scheme $scheme added."
		echo "You should re-run ./autogen.sh and ./configure";;

	addcrl )
	
		echo "Updating $rootdir/include/crl_handles.h"
		# @XXX This should change when CRLs are completely separated from group signature schemes
		sed "s/#include \"crl.h\"$/#include \"crl.h\"\n#include \"groupsig\/${scheme}\/crl.h\"/" crl_handles.h >crl_handles.h.tmp
		mv crl_handles.h.tmp crl_handles.h
		num=$((`grep "#define CRL_HANDLES_N" crl_handles.h | cut -d' ' -f3`+1))
		sed "s/#define CRL_HANDLES_N .*$/#define CRL_HANDLES_N $num/" crl_handles.h > crl_handles.h.tmp	
		mv crl_handles.h.tmp crl_handles.h
		sed "s/\(const crl_handle_t \*CRL_HANDLES\[CRL_HANDLES_N\] = {\)/\1 \n  \&${scheme},/" crl_handles.h > crl_handles.h.tmp
		mv crl_handles.h.tmp crl_handles.h


		echo "CRL type $scheme added.";;

	addgml )

		echo "Updating $rootdir/include/gml_handles.h"
		# @XXX This should change when GMLs are completely separated from group signature schemes
		sed "s/#include \"gml.h\"$/#include \"gml.h\"\n#include \"groupsig\/${scheme}\/gml.h\"/" gml_handles.h >gml_handles.h.tmp
		mv gml_handles.h.tmp gml_handles.h
		num=$((`grep "#define GML_HANDLES_N" gml_handles.h | cut -d' ' -f3`+1))
		sed "s/#define GML_HANDLES_N .*$/#define GML_HANDLES_N $num/" gml_handles.h > gml_handles.h.tmp	
		mv gml_handles.h.tmp gml_handles.h
		sed "s/\(const gml_handle_t \*GML_HANDLES\[GML_HANDLES_N\] = {\)/\1 \n  \&${scheme},/" gml_handles.h > gml_handles.h.tmp
		mv gml_handles.h.tmp gml_handles.h

		echo "GML type $scheme added.";;

	addid )

		echo "Updating $rootdir/include/identity_handles.h"
		# @XXX This should not be necessary when IDENTITYs are completely 
		# separated from group signature schemes
		sed "s/#include \"identity.h\"$/#include \"identity.h\"\n#include \"groupsig\/${scheme}\/identity.h\"/" identity_handles.h >identity_handles.h.tmp
		mv identity_handles.h.tmp identity_handles.h
		num=$((`grep "#define IDENTITY_HANDLES_N" identity_handles.h | cut -d' ' -f3`+1))
		sed "s/#define IDENTITY_HANDLES_N .*$/#define IDENTITY_HANDLES_N $num/" identity_handles.h > identity_handles.h.tmp	
		mv identity_handles.h.tmp identity_handles.h
		sed "s/\(const identity_handle_t \*IDENTITY_HANDLES\[IDENTITY_HANDLES_N\] = {\)/\1 \n  \&${scheme},/" identity_handles.h > identity_handles.h.tmp
		mv identity_handles.h.tmp identity_handles.h

		echo "Identity type $scheme added.";;

	* )
		echo "Unsupported action."
		exit $E_UNSUPPORTED;
esac

exit $E_OK;
