#!/bin/bash

# --- Configuration ---
FINAL_ZIP_NAME="full_wo_corpus_cmd_harness.zip"
SOURCE_ZIP_PATTERN='2025*_wo_corpus_cmd_harness.zip'
MAIN_TEMP_DIR="temp_merged_contents_root"
EXPERIMENTS_DIR="experiments"

pushd ${EXPERIMENTS_DIR} || {
  echo "Failed to change directory to $EXPERIMENTS_DIR. Exiting."
  exit 1
}

# --- Helper Functions ---
# Logs an informational message
info() {
  echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Logs a warning message
warn() {
  echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# Logs an error message and exits the script
error_exit() {
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
  # Clean up MAIN_TEMP_DIR if it exists, as an error occurred.
  # This prevents leaving a potentially large temp dir on critical failure.
  if [ -d "$MAIN_TEMP_DIR" ]; then
    warn "Attempting to clean up $MAIN_TEMP_DIR due to error..."
    # Use a subshell for rm -rf to avoid issues if the current directory is the temp dir
    (rm -rf "$MAIN_TEMP_DIR") || warn "Failed to remove $MAIN_TEMP_DIR during error cleanup. Manual intervention may be required."
  fi
  exit 1
}

# --- Main Script ---
info "Starting merge process."
info "Final zip name: $FINAL_ZIP_NAME"
info "Source zip pattern: $SOURCE_ZIP_PATTERN"
info "Main temporary directory: $MAIN_TEMP_DIR"

# 1. Setup Main Temporary Directory
if [ -d "$MAIN_TEMP_DIR" ]; then
  info "Removing existing main temporary directory: $MAIN_TEMP_DIR"
  # Use a subshell for rm -rf to avoid issues if the current directory is the temp dir
  if ! (rm -rf "$MAIN_TEMP_DIR"); then
    error_exit "Failed to remove existing $MAIN_TEMP_DIR. Please check permissions or locks."
  fi
fi

info "Creating main temporary directory: $MAIN_TEMP_DIR"
if ! mkdir -p "$MAIN_TEMP_DIR"; then
  error_exit "Failed to create main temporary directory: $MAIN_TEMP_DIR"
fi

# Get absolute path for MAIN_TEMP_DIR for robust cd/rsync operations
# This is done after creation to ensure the directory exists
MAIN_TEMP_DIR_ABS="$(cd "$MAIN_TEMP_DIR" && pwd)"
if [ -z "$MAIN_TEMP_DIR_ABS" ]; then
  error_exit "Could not determine absolute path for $MAIN_TEMP_DIR after creation."
fi
info "Absolute path for temporary directory: $MAIN_TEMP_DIR_ABS"

PROCESSED_ZIP_COUNT=0
SUCCESSFUL_MERGE_COUNT=0

# 2. Process Each Source Zip
info "Looking for source zip files matching pattern: '$SOURCE_ZIP_PATTERN' in current directory ($(pwd))"

# Use a robust way to find files matching the pattern, handling spaces/special chars.
# find . -maxdepth 1 -name "$SOURCE_ZIP_PATTERN" -print0 | while IFS= read -r -d '' corpus_zip; do
# A simpler approach using shell globbing directly, which is generally safe for filenames
# unless they start with '-' or contain wildcards that shouldn't be expanded.
# Given the pattern '2025*_wo_corpus_cmd_harness.zip', direct globbing should be fine.
source_zips=($SOURCE_ZIP_PATTERN) # Store matching files in an array

if [ ${#source_zips[@]} -eq 0 ] || [ "${source_zips[0]}" = "$SOURCE_ZIP_PATTERN" ] && [ ! -e "$SOURCE_ZIP_PATTERN" ]; then
  info "No zip files matching the pattern '$SOURCE_ZIP_PATTERN' were found."
  # Clean up empty main temp dir
  rmdir "$MAIN_TEMP_DIR_ABS" 2>/dev/null ||
    warn "Main temporary directory '$MAIN_TEMP_DIR_ABS' was not removed (it might not be empty or an error occurred)."
  info "Merge process finished. No final zip created."
  exit 0
fi

for corpus_zip in "${source_zips[@]}"; do
  # Check if the file actually exists and is a regular file before processing
  if [ -f "$corpus_zip" ]; then
    info "Processing zip file: $corpus_zip"
    PROCESSED_ZIP_COUNT=$((PROCESSED_ZIP_COUNT + 1))

    # Unzip contents into the temporary directory. -q for quiet.
    # This extracts contents directly into MAIN_TEMP_DIR_ABS without subdirs for each zip.
    if unzip -j -q "$corpus_zip" -d "$MAIN_TEMP_DIR_ABS"; then
      info "Successfully unzipped $corpus_zip into $MAIN_TEMP_DIR_ABS."
      SUCCESSFUL_MERGE_COUNT=$((SUCCESSFUL_MERGE_COUNT + 1))
    else
      warn "Failed to unzip $corpus_zip into $MAIN_TEMP_DIR_ABS. Skipping this file."
      # Continue loop to process next file
    fi
  else
    # This case should ideally not happen with the array approach unless the pattern
    # matched something that isn't a file or disappeared between globbing and processing.
    warn "Skipping '$corpus_zip' as it is not a regular file or does not exist."
  fi
done

# --- Step 3: Create the final combined zip file ---

if [ "$PROCESSED_ZIP_COUNT" -eq 0 ]; then
  # This case is already handled by the check before the loop, but kept for safety.
  info "No zip files matching the pattern '$SOURCE_ZIP_PATTERN' were found."
  # Clean up empty main temp dir
  rmdir "$MAIN_TEMP_DIR_ABS" 2>/dev/null ||
    warn "Main temporary directory '$MAIN_TEMP_DIR_ABS' was not removed (it might not be empty or an error occurred)."
  info "Merge process finished. No final zip created."
  exit 0
fi

if [ "$SUCCESSFUL_MERGE_COUNT" -eq 0 ]; then
  info "Processed $PROCESSED_ZIP_COUNT zip file(s), but no content was successfully merged into '$MAIN_TEMP_DIR_ABS'."
  info "Final zip file '$FINAL_ZIP_NAME' will not be created."
  rm -rf "$MAIN_TEMP_DIR_ABS" # Clean up main temp dir
  info "Merge process finished."
  exit 0
fi

# Check if MAIN_TEMP_DIR_ABS has any content before zipping
# find "$MAIN_TEMP_DIR_ABS" -mindepth 1 -print -quit 2>/dev/null checks if there's at least one entry (file/dir)
if ! find "$MAIN_TEMP_DIR_ABS" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
  info "Main temporary directory '$MAIN_TEMP_DIR_ABS' is empty after processing. No files to zip."
  info "Final zip file '$FINAL_ZIP_NAME' will not be created."
  rm -rf "$MAIN_TEMP_DIR_ABS" # Clean up empty dir
  info "Merge process finished."
  exit 0
fi

info "Consolidated contents from $SUCCESSFUL_MERGE_COUNT out of $PROCESSED_ZIP_COUNT processed zip file(s) into $MAIN_TEMP_DIR_ABS."
info "Creating the final zip file: $FINAL_ZIP_NAME (from contents of $MAIN_TEMP_DIR_ABS)"

# Determine the absolute path for the final zip file
FINAL_ZIP_PATH_ABS="$(pwd)/$FINAL_ZIP_NAME"

# Use a subshell for 'cd' to ensure we return to the original directory after zipping.
# Zip the *contents* of MAIN_TEMP_DIR_ABS.
(
  cd "$MAIN_TEMP_DIR_ABS" || {
    warn "Critical: Could not navigate to $MAIN_TEMP_DIR_ABS to create zip."
    exit 1 # Exit the subshell with error
  }
  # -r for recursive, -q for quiet. '.' refers to all contents of the current directory ($MAIN_TEMP_DIR_ABS).
  # The zip file is created at the specified absolute path.
  # Use -y to store symbolic links as links (if any)
  if zip -rqy "$FINAL_ZIP_PATH_ABS" .; then
    info "Successfully created final combined zip file: $FINAL_ZIP_PATH_ABS"
    exit 0 # Success for subshell
  else
    warn "Zip command failed to create '$FINAL_ZIP_PATH_ABS'."
    exit 1 # Failure for subshell
  fi
)
ZIP_COMMAND_EXIT_STATUS=$?

# --- Step 4: Clean up the main temporary directory ---
if [ $ZIP_COMMAND_EXIT_STATUS -eq 0 ]; then
  info "Cleaning up main temporary directory: $MAIN_TEMP_DIR_ABS"
  # Use a subshell for rm -rf to avoid issues if the current directory is the temp dir
  if ! (rm -rf "$MAIN_TEMP_DIR_ABS"); then
    warn "Failed to remove $MAIN_TEMP_DIR_ABS. Please remove it manually."
  else
    info "Main temporary directory removed."
  fi
else
  warn "Main temporary directory '$MAIN_TEMP_DIR_ABS' was NOT removed due to an error ($ZIP_COMMAND_EXIT_STATUS) during final zip creation."
  warn "You may inspect its contents at: $MAIN_TEMP_DIR_ABS"
fi

# --- Final Exit ---
if [ $ZIP_COMMAND_EXIT_STATUS -ne 0 ]; then
  error_exit "Merge process finished with errors during final zip creation."
else
  info "Merge process finished successfully."
  exit 0
fi

popd || {
  warn "Failed to return to the original directory. You may need to do this manually."
  exit 1
}
