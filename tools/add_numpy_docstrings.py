"""
Script to add NumPy-style docstring stubs to Python files in the project.
Scans for classes and functions without docstrings and inserts placeholders.
Usage: python tools/add_numpy_docstrings.py [--dry-run]
"""
import ast
import os
import sys

def add_docstrings_to_file(filepath, dry_run=False):
    '''Function add_docstrings_to_file - description.'''
    with open(filepath, 'r', encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source)
    class DocInserter(ast.NodeTransformer):
        '''Class DocInserter - description.'''
        def visit_FunctionDef(self, node):
            '''Function visit_FunctionDef - description.'''
            # skip if has docstring
            if not ast.get_docstring(node):
                doc = ast.Expr(value=ast.Constant(value="""
Parameters
----------

Returns
-------

"""))
                node.body.insert(0, doc)
            return node
        def visit_ClassDef(self, node):
            '''Function visit_ClassDef - description.'''
            if not ast.get_docstring(node):
                doc = ast.Expr(value=ast.Constant(value="""
Attributes
----------

Methods
-------

"""))
                node.body.insert(0, doc)
            return node
    new_tree = DocInserter().visit(tree)
    ast.fix_missing_locations(new_tree)
    import astor
    new_source = astor.to_source(new_tree)
    if dry_run:
        print(f"--- {filepath} ---")
        print(new_source)
    else:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_source)

def main():
    '''Function main - description.'''
    dry = '--dry-run' in sys.argv
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    for subdir, dirs, files in os.walk(root):
        if 'tools' in subdir or '__pycache__' in subdir:
            continue
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(subdir, file)
                add_docstrings_to_file(path, dry_run=dry)
    print('Docstring insertion complete.')

if __name__ == '__main__':
    main()
