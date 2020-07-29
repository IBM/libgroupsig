#!/bin/bash

awk '
	BEGIN { 
		t=0 
	} 
	{ 
		t=(t+$2-$1);
		s[NR]=($2-$1); 
	} 
	END { 
		avg = t/NR;
		std = 0;
		for (i=0; i<NR; i++) {
			std += ((s[i]-avg)*(s[i]*avg)/NR)
		}
		std = sqrt(std)
		printf "Average time: %2f\nStandard deviation: %2f\n", avg, std; 
	}
' $1
