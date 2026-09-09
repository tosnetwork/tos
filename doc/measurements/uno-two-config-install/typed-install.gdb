set pagination off
set confirm off
set breakpoint pending on
break /home/tomi/tos-m2/validator/manager-disk.cpp:324
commands
silent
printf "FINAL_TYPED_BRANCH=CandidateReject\n"
print reject
bt 3
continue
end
run
