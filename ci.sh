#!/bin/bash
############################################################
# Script to perform the "Continuous Integration" validation
############################################################
# NOTE: 
# Issues on the skill "secure-jwt-validation" are ignored because this one is clean but it raise findings 
# by SkillSpector due to the type of data handled by the skill (access token so credentials).
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
# Update the skills catalog
echo "[+] Generate the skills descriptor file (catalog)" 
skills_descriptor="skills_catalog.xml"
skills_folders=""
for skill_folder in $(ls $skills_base_folder)
do
    skills_folders="$skills_base_folder/$skill_folder $skills_folders"
done
pyenv/bin/agentskills to-prompt $skills_folders > $skills_descriptor
sed -i 's|/home/runner/work/code-assistant-skills-security-utils/code-assistant-skills-security-utils|https://github.com/righettod/code-assistant-skills-security-utils/tree/main|g' $skills_descriptor
cat $skills_descriptor
echo "[+] Update the skills catalog HTML representation"
xsltproc skills_catalog.xsl skills_catalog.xml > docs/index.html
cd .claude/
rm ../docs/skills.zip 2>/dev/null
date > build-date.txt
zip -r ../docs/skills.zip build-date.txt skills/ 
rm build-date.txt
cd ..
echo "[+] Scan the skills with NVIDIA/SkillSpector"
git clone --depth 1 https://github.com/NVIDIA/SkillSpector.git /tmp/skillspector
docker build -t skillspector /tmp/skillspector
issue_found_count=$(docker run --rm -v "$PWD:/scan" skillspector scan /scan/docs/skills.zip --no-llm --format json | jq '[.issues[] | select(.location.file != "skills/secure-jwt-validation/SKILL.md")] | length')
rm -rf /tmp/skillspector
if [ $issue_found_count -ne 0 ]
then
  echo "[!] SkillSpector identified $issue_found_count issues:"
  docker run --rm -v "$PWD:/scan" skillspector scan /scan/docs/skills.zip --no-llm --format json | jq '.issues[] | select(.location.file != "skills/secure-jwt-validation/SKILL.md")'
  exit 1
else
  echo "[V] SkillSpector identified no issue!"
  exit 0
fi
