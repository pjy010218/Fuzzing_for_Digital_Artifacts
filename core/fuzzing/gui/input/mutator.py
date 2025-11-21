import subprocess
import os

class InputMutator:
    """
    Wrapper around Radamsa to generate mutated inputs 
    from valid seed files.
    """
    def __init__(self, seed_dir: str):
        self.seed_dir = seed_dir

    def generate(self, output_path: str, count: int = 1):
        """
        Takes valid files (seeds) and makes them 'interesting' 
        using Radamsa, then saves to output_path.
        """
        # Get a list of seed files
        seeds = [os.path.join(self.seed_dir, f) 
                 for f in os.listdir(self.seed_dir)]
        
        if not seeds:
            raise ValueError("No seed files found!")

        # Call Radamsa as a subprocess
        # cmd: radamsa --count 1 --output output.dat seed1.dat seed2.dat
        cmd = ["radamsa", "--count", str(count), "--output", output_path] + seeds
        
        subprocess.run(cmd, check=True)
        return output_path