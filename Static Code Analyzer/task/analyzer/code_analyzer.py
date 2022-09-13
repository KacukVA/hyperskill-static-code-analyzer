from __future__ import annotations
import os
import re
import sys
import ast
from collections import defaultdict


class PepAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.stats: dict[str, dict[int, list]] = {
            "variables": defaultdict(list),
            "parameters": defaultdict(list),
            "is_constant_default": defaultdict(list),
        }

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.stats["variables"][node.lineno].append(node.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for a in node.args.args:
            self.stats["parameters"][node.lineno].append(a.arg)
        for a in node.args.defaults:
            self.stats["is_constant_default"][node.lineno].append(isinstance(a, ast.Constant))
        self.generic_visit(node)

    def get_parameters(self, lineno: int) -> list:
        return self.stats["parameters"][lineno]

    def get_variables(self, lineno: int) -> list:
        return self.stats["variables"][lineno]

    def get_mutable_defaults(self, lineno: int) -> str:
        for param_name, is_default in zip(self.stats["parameters"][lineno], self.stats["is_constant_default"][lineno]):
            if not is_default:
                return param_name
        return ""


def check_s001(number: int, string: str) -> str | None:
    """
    [S001]: To long line
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    if len(string) > 79:
        return f'Line {number}: S001 Too long'
    return None


def check_s002(number: int, string: str) -> str | None:
    """
    [S002]: Indentation is not a multiple of four
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    if re.match(r"(?!^( {4})*[^ ])", string):
        return f'Line {number}: S002 Indentation is not a multiple of four'
    return None


def check_s003(number: int, string: str) -> str | None:
    """
    [S003]: Unnecessary semicolon after a statement (note that semicolons are acceptable in comments)
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    match = re.findall(r'; *#', string)
    if match:
        return f'Line {number}: S003 Unnecessary semicolon'
    if string.strip().endswith(';') and string.find('#') == -1:
        return f'Line {number}: S003 Unnecessary semicolon'
    return None


def check_s004(number: int, string: str) -> str | None:
    """
    [S004]: Less than two spaces before inline comments
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    hashtag = string.find('#')
    if hashtag > 0 and string[hashtag-2:hashtag] != '  ':
        return f'Line {number}: S004 At least two spaces required before inline comments'
    return None


def check_s005(number: int, string: str) -> str | None:
    """
    [S005]: TO DO found
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    if re.findall(r'#.*todo', string, re.I):
        return f'Line {number}: S005 TODO found'
    return None


def check_s006(number: int, string: str) -> str | None:
    """
    [S006]: More than two blank lines preceding a code line (applies to the first non-empty line)
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    global blank_line_counter
    if len(string.strip()) == 0:
        blank_line_counter += 1
    else:
        if blank_line_counter > 2:
            blank_line_counter = 0
            return f'Line {number}: S006 More than two blank lines used before this line'
        else:
            blank_line_counter = 0
    return None


def check_s007(number: int, string: str) -> str | None:
    """
    [S007]: Too many spaces after construction_name (def or class)
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    statement = None
    if string.find('def') != -1:
        def_match = re.match(r'\s*def\s{2}', string)
        if def_match and len(def_match.group()):
            statement = 'def'
    if string.find('class') != -1:
        class_match = re.match(r'\s*class\s{2}', string)
        if class_match and len(class_match.group()):
            statement = 'class'
    if statement:
        return f"Line {number}: S007 Too many spaces after '{statement}'"
    else:
        return None


def check_s008(number: int, string: str) -> str | None:
    """
    [S008]: Class name class_name should be written in CamelCase
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    class_name = re.findall(r' *class *([-_\w]+)', string)
    if len(class_name):
        match = re.findall(r'[-_]', class_name[0])
        if len(match) or class_name[0][0].upper() + class_name[0][1::] != class_name[0]:
            return f"Line {number}: S008 Class name '{class_name[0]}' should use CamelCase"
    return None


def check_s009(number: int, string: str) -> str | None:
    """
    [S009]: Function name function_name should be written in snake_case
        :param number: line number
        :param string: line for check
        :return: error description | None
    """
    func_name = re.findall(r' *def *([-_\w]+)', string)
    if len(func_name):
        match = re.findall(r'[A-Z-]', func_name[0])
        if len(match):
            return f"Line {number}: S009 Function name '{func_name[0]}' should use snake_case"
    return None


def check_s010(number: int, analyzer: PepAnalyzer) -> str | None:
    """
    [S0010]: Argument name arg_name should be written in snake_case
        :param number: line number
        :param analyzer: class PepAnalyzer
        :return: error description | None
    """
    for parameter in analyzer.get_parameters(number):
        if not re.match(r"[a-z_]+", parameter):
            return f"Line {number}: S010 Argument name '{parameter}' should be snake_case"
    return None


def check_s011(number: int, analyzer: PepAnalyzer) -> str | None:
    """
    [S011]: Variable var_name should be written in snake_case
        :param number: line number
        :param analyzer: class PepAnalyzer
        :return: error description | None
    """
    for variable in analyzer.get_variables(number):
        if not re.match(r"[a-z_]+", variable):
            return f"Line {number}: S011 Variable '{variable}' in function should be snake_case"
    return None


def check_s012(number: int, analyzer: PepAnalyzer) -> str | None:
    """
    [S012]: The default argument value is mutable
        :param number: line number
        :param analyzer: class PepAnalyzer
        :return: error description | None
    """
    if analyzer.get_mutable_defaults(number):
        return f"Line {number}: S012 Default argument value is mutable"
    return None


def validate_file(file_path):
    output = list()
    global blank_line_counter
    blank_line_counter = 0
    with open(file_path, 'r') as f:
        tree = ast.parse(f.read())
        pep_analyzer = PepAnalyzer()
        pep_analyzer.visit(tree)
        f.seek(0)
        for index, line in enumerate(f, start=1):
            output.append(check_s001(index, line))
            output.append(check_s002(index, line))
            output.append(check_s003(index, line))
            output.append(check_s004(index, line))
            output.append(check_s005(index, line))
            output.append(check_s006(index, line))
            output.append(check_s007(index, line))
            output.append(check_s008(index, line))
            output.append(check_s009(index, line))
            output.append(check_s010(index, pep_analyzer))
            output.append(check_s011(index, pep_analyzer))
            output.append(check_s012(index, pep_analyzer))
    print(*(file_path + ': ' + x for x in output if x is not None), sep='\n')


if __name__ == '__main__':
    blank_line_counter = 0
    script, path = sys.argv
    if path.endswith('.py'):
        validate_file(path)
    else:
        for root, dirs, files in sorted(os.walk(path)):
            for file in sorted(files):
                if file.endswith('.py'):
                    validate_file(root + '/' + file)
