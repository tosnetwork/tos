# noinspection PyUnresolvedReferences
import lldb


def call_cpp_debug_print(valobj, arg_type: str):
    type = valobj.GetType()
    if type.is_reference or type.is_pointer:
        addr = valobj.Dereference().GetAddress()
    else:
        addr = valobj.GetAddress()
    if not addr.IsValid():
        return "nullptr"

    s = valobj.GetFrame().EvaluateExpression('debug_print(({}*){})'.format(arg_type, addr)).GetSummary()
    s = str(s)[1:-1]  # trim quotes

    if "{enum.Op.cl}" in s:
        s = s.replace("{enum.Op.cl}", valobj.GetChildMemberWithName("cl").GetValue())
    if "{enum.AsmOp.t}" in s:
        s = s.replace("{enum.AsmOp.t}", valobj.GetChildMemberWithName("t").GetValue())
    return s


def print_td_RefInt256(valobj, internal_dict, options):
    n = valobj.EvaluateExpression("ptr.value.n").GetValueAsUnsigned()
    if n == 0:
        return "0"
    if n == 1:
        return valobj.EvaluateExpression("ptr.value.digits[0]").GetValueAsUnsigned()
    return "n=" + str(n)


def print_ast_vertex(valobj, internal_dict, options):
    type = valobj.GetType()
    if type.is_reference or type.is_pointer:
        addr = valobj.Dereference().GetAddress()
    else:
        addr = valobj.GetAddress()
    if not addr.IsValid():
        return "nullptr"

    s = valobj.GetFrame().EvaluateExpression('debug_print((tol::ASTNodeBase*){})'.format(addr)).GetSummary()
    s = str(s)[1:-1]  # trim quotes

    return s


def __lldb_init_module(debugger, _):
    types_with_debug_print = [
        'tol::Op',
        'tol::OpList',
        'tol::TypeData',
        'tol::VarDescr',
        'tol::TmpVar',
        'tol::VarDescrList',
        'tol::AsmOp',
        'tol::AsmOpList',
        'tol::Stack',
        'tol::SrcRange',
        'tol::LocalVarData',
        'tol::FunctionData',
        'tol::GlobalVarData',
        'tol::GlobalConstData',
        'tol::AliasDeclarationData',
        'tol::StructFieldData',
        'tol::StructData',
        'tol::EnumMemberData',
        'tol::EnumDefData',
        'tol::FlowContext',
        'tol::SinkExpression',
        'tol::InfoAboutExpr',
        'tol::GenericsDeclaration',
        'tol::GenericsSubstitutions',
    ]
    for arg_type in types_with_debug_print:
        debugger.HandleCommand('type summary add --python-script "return lldb_addons.call_cpp_debug_print(valobj, \'{}\')" {}'.format(arg_type, arg_type))

    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTNodeBase')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTNodeDeclaredTypeBase')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTNodeExpressionBase')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTNodeStatementBase')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTTypeLeaf')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTTypeVararg')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTExprLeaf')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTExprUnary')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTExprBinary')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTExprVararg')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTStatementUnary')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" tol::ASTStatementVararg')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" -x "^tol::V<.+>$"')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_ast_vertex" -x "^tol::Vertex<.+>$"')
    debugger.HandleCommand('type summary add --python-function "lldb_addons.print_td_RefInt256" td::RefInt256')
