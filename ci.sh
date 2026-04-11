#!/bin/bash
############################################################
# Script to perform the "Continuous Integration" validation
############################################################
# Create VENV
python -m venv pyenv
source pyenv/bin/activate
# Install the validation tool
pip install skills-ref
# Validate all skills
skills_base_folder=".claude/skills"
for skill_folder in $(ls $skills_base_folder)
do
    skill_file="$skills_base_folder/$skill_folder/SKILL.md"
    echo "[+] Validate skill file: $skill_file" 
    pyenv/bin/agentskills validate $skill_file
done
