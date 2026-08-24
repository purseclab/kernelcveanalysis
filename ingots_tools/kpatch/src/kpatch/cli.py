import typer

from .dataset import analyze_dataset

def run():
    analyze_dataset()

def main():
    typer.run(run)
