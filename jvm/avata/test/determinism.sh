#!/bin/sh

vg="nice valgrind --leak-check=full --num-callers=32 \
--freelist-vol=100000000 --error-exitcode=1"

ld_path=${1}; shift
vm=${1}; shift
mode=${1}; shift
flags=${1}; shift
tests=${@}

log=determinism-log.txt
tmp_dir=determinism-tmp-$$

if [ -n "${ld_path}" ]; then
  export ${ld_path}
fi

rm -rf "${tmp_dir}"
mkdir "${tmp_dir}" || exit 1
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

echo -n "" >${log}

printf "%20s------- Determinism replay tests -------\n" ""
for test in ${tests}; do
  printf "%32s: " "${test}"

  first="${tmp_dir}/${test}.1"
  second="${tmp_dir}/${test}.2"

  case ${mode} in
    debug|debug-fast|fast|small )
      ${vm} ${flags} ${test} >${first} 2>&1
      first_status=${?}
      ${vm} ${flags} ${test} >${second} 2>&1
      second_status=${?};;

    stress* )
      ${vg} ${vm} ${flags} ${test} >${first} 2>&1
      first_status=${?}
      ${vg} ${vm} ${flags} ${test} >${second} 2>&1
      second_status=${?};;

    * )
      echo "unknown mode: ${mode}" >&2
      exit 1;;
  esac

  if [ "${first_status}" = "0" ] \
      && [ "${second_status}" = "0" ] \
      && cmp -s "${first}" "${second}"; then
    echo "success"
  else
    echo "fail"
    {
      echo "determinism replay failed for ${test}"
      echo "first_status=${first_status}"
      echo "second_status=${second_status}"
      echo "--- diff ---"
      diff -u "${first}" "${second}" || true
      echo "--- first ---"
      cat "${first}"
      echo "--- second ---"
      cat "${second}"
    } >> ${log}
    trouble=1
  fi
done

echo

if [ -n "${trouble}" ]; then
  printf "see `pwd`/${log} for determinism replay output\n"
  exit -1
fi
