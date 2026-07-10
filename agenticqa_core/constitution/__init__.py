"""
Wolfpack Engineering Constitution.

Single source of truth for how every agent works across every Wolfpack repo
and every runtime. Import the loader to render the constitution for any agent
runtime or to check a shell command against the machine-enforced rules.

    from agenticqa_core.constitution import loader

    text = loader.render_markdown()          # inject into a system prompt
    verdict = loader.check_bash_command(cmd)  # deterministic PreToolUse gate
"""

from . import loader

__all__ = ["loader"]
