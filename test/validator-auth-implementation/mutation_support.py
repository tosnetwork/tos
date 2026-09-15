"""Match a single C++ token sequence independently of formatter whitespace."""
import re
TOKEN=re.compile(r'"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|[0-9]+|!=|==|>=|<=|\|\||&&|::|->|[^\s]')
def replace_once(source,before,after):
 tokens=TOKEN.findall(before)
 pattern=re.compile(r'\s*'.join(re.escape(token) for token in tokens))
 matches=list(pattern.finditer(source))
 if len(matches)!=1:raise ValueError(('mutation-match',before,len(matches)))
 match=matches[0]
 return source[:match.start()]+after+source[match.end():]
