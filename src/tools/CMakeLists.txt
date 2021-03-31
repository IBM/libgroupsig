include_directories ("${PROJECT_SOURCE_DIR}/src/include"
                     "${PROJECT_SOURCE_DIR}/src")

# group_create
add_executable (group_create group_create.c)
target_include_directories (group_create
				PRIVATE ${MCL_INCLUDE_DIRS}
				PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (group_create groupsig
		      		    ${OPENSSL_LIBRARIES}
				    ${MCL_LIBRARY}
				    ${MCL384_256_LIBRARY})

# join
add_executable (join join.c)
target_include_directories (join
				PRIVATE ${MCL_INCLUDE_DIRS}	
                                PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (join groupsig
		      	    ${OPENSSL_LIBRARIES}
			    ${MCL_LIBRARY}
			    ${MCL384_256_LIBRARY})

## open
add_executable (open open.c)
target_include_directories (open
				PRIVATE ${MCL_INCLUDE_DIRS}	
                                PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (open groupsig
		      	      ${OPENSSL_LIBRARIES}
			      ${MCL_LIBRARY}
			      ${MCL384_256_LIBRARY})			  

## revoke
#add_executable (revoke revoke.c)
#target_include_directories (revoke
#				PRIVATE ${MCL_INCLUDE_DIRS}	
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (revoke groupsig
#		      	      ${OPENSSL_LIBRARIES}
#			      ${MCL_LIBRARY}
#			      ${MCL384_256_LIBRARY})

# same_signer
#add_executable (same_signer same_signer.c)
#target_include_directories (same_signer
#				PRIVATE ${MCL_INCLUDE_DIRS}	
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (same_signer groupsig
#		      		   ${OPENSSL_LIBRARIES}
#				   ${MCL_LIBRARY})

# sign
add_executable (sign sign.c)
target_include_directories (sign
				PRIVATE ${MCL_INCLUDE_DIRS}
                                PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (sign groupsig
		      	    ${OPENSSL_LIBRARIES}
			    ${MCL_LIBRARY}
			    ${MCL384_256_LIBRARY})

# verify
add_executable (verify verify.c)
target_include_directories (verify
				PRIVATE ${MCL_INCLUDE_DIRS}
                                PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (verify groupsig
		      	      ${OPENSSL_LIBRARIES}
			      ${MCL_LIBRARY}
			      ${MCL384_256_LIBRARY})

## trace
#add_executable (trace trace.c)
#target_include_directories (trace
#				PRIVATE ${MCL_INCLUDE_DIRS}
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (trace groupsig
#		      	     ${OPENSSL_LIBRARIES}
#			     ${MCL_LIBRARY}
#			     ${MCL384_256_LIBRARY})
#
## claim
#add_executable (claim claim.c)
#target_include_directories (claim
#				PRIVATE ${MCL_INCLUDE_DIRS}
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (claim groupsig
#		      	     ${OPENSSL_LIBRARIES}
#			     ${MCL_LIBRARY}
#			     ${MCL384_256_LIBRARY})
#
## claim_verify
#add_executable (claim_verify claim_verify.c)
#target_include_directories (claim_verify
#				PRIVATE ${MCL_INCLUDE_DIRS}
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (claim_verify groupsig
#		      		    ${OPENSSL_LIBRARIES}
#				    ${MCL_LIBRARY}
#				    ${MCL384_256_LIBRARY})

# blind
add_executable (blind blind.c)
target_include_directories (blind
				PRIVATE ${MCL_INCLUDE_DIRS}
                                PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (blind groupsig
		      	     ${OPENSSL_LIBRARIES}
			     ${MCL_LIBRARY}
			     ${MCL384_256_LIBRARY})

# convert
add_executable (convert convert.c)
target_include_directories (convert
				PRIVATE
					${MCL_INCLUDE_DIRS}
                                	${OPENSSL_INCLUDE_DIR})
target_link_libraries (convert
			groupsig
		      	       	${OPENSSL_LIBRARIES}
			       	${MCL_LIBRARY}
				${MCL384_256_LIBRARY})

# unblind
add_executable (unblind unblind.c)
target_include_directories (unblind
				PRIVATE
					${MCL_INCLUDE_DIRS}
                                	${OPENSSL_INCLUDE_DIR})
target_link_libraries (unblind
			groupsig
		      	       	${OPENSSL_LIBRARIES}
			       	${MCL_LIBRARY}
				${MCL384_256_LIBRARY})

# benchmarks
add_executable (benchmarks benchmarks.c)
target_include_directories (benchmarks
				PRIVATE
					${MCL_INCLUDE_DIRS}
                                	${OPENSSL_INCLUDE_DIR})
target_link_libraries (benchmarks
			groupsig
			base64
		      	       	${OPENSSL_LIBRARIES}
			       	${MCL_LIBRARY}
				${MCL384_256_LIBRARY})

# print_key
#add_executable (print_key print_key.c)
#target_include_directories (print_key
#				PRIVATE ${MCL_INCLUDE_DIRS}
#                                PRIVATE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries (print_key groupsig
#		      		 ${OPENSSL_LIBRARIES}
#				 ${MCL_LIBRARY})
