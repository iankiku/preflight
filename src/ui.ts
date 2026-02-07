/**
 * ClawSec UI Utilities
 * TTY detection, terminal hyperlinks, and interactive mode gating.
 */

export function isInteractive(quiet: boolean): boolean {
  if (quiet) return false;
  if (process.env.CI) return false;
  if (process.env.NO_COLOR) return false;
  if (!process.stdout.isTTY) return false;
  return true;
}

/**
 * Wrap text in an OSC 8 clickable hyperlink for terminals that support it
 * (iTerm2, Warp, GNOME Terminal, Windows Terminal, Hyper, etc.)
 * Falls back to plain text in terminals that don't — they just ignore the escape.
 */
export function link(text: string, url: string): string {
  return `\x1b]8;;${url}\x07${text}\x1b]8;;\x07`;
}

/** Convert an absolute file path to a file:// URL. */
export function fileUrl(absolutePath: string): string {
  return `file://${absolutePath}`;
}
