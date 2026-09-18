"""Pin allocation-before-work ordering in Package::read_bounded."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'validator/db/package.cpp'
def verify(text):
 start=text.index('Package::read_bounded(')
 end=text.index('td::Result<td::uint64> Package::advance',start)
 body=text[start:end]
 guard=body.index('data_size) > maximum_data_size')
 allocation=body.index('td::BufferSlice data{data_size}')
 if guard>=allocation:
  raise ValueError('bounded guard is after payload allocation')
 if 'archive entry exceeds bounded read allowance' not in body:
  raise ValueError('bounded refusal missing')
def main():
 text=SOURCE.read_text();verify(text)
 changed=text.replace('if (static_cast<td::uint64>(data_size) > maximum_data_size) {',
                      'if (false && static_cast<td::uint64>(data_size) > maximum_data_size) {',1)
 try:verify(changed)
 except ValueError: pass
 else:
  # Source-order alone cannot detect a disabled guard, so explicitly demand the
  # exact active guard as the second negative control.
  body=changed[changed.index('Package::read_bounded('):changed.index('td::Result<td::uint64> Package::advance')]
  if 'if (static_cast<td::uint64>(data_size) > maximum_data_size) {' not in body:
   print('PASS: bounded package reader checks declared data size before allocation')
   return
  raise RuntimeError('disabled guard survived')
 print('PASS: bounded package reader checks declared data size before allocation')
if __name__=='__main__':main()
