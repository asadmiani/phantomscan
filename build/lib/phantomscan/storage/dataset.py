"""
Dataset Storage Module
Autonomous Security Platform

- Stores vulnerability training data
- Used for AI model retraining
"""

import json
import os


class DatasetManager:

    def __init__(self, file_name="ai_dataset.json"):
        self.file_name = file_name
        self._initialize()

    # ------------------------------------------
    # Initialize Dataset File
    # ------------------------------------------

    def _initialize(self):

        if not os.path.exists(self.file_name):
            with open(self.file_name, "w") as f:
                json.dump([], f)

    # ------------------------------------------
    # Add Entry
    # ------------------------------------------

    def add_entry(self, finding):

        with open(self.file_name, "r") as f:
            data = json.load(f)

        data.append(finding)

        with open(self.file_name, "w") as f:
            json.dump(data, f, indent=4)

    # ------------------------------------------
    # Load Dataset
    # ------------------------------------------

    def load(self):

        with open(self.file_name, "r") as f:
            return json.load(f)
