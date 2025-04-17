import requests
import json
import math
from collections import defaultdict
from tabulate import tabulate # For nice table formatting (install with: pip install tabulate)
 
# --- Configuration ---
 
# --- !!! SET THE REPOSITORY ID HERE !!! ---
# Example: "e7af4986-183d-4764-8bd2-1d6b47f87d99"
REPO_ID = "e7af4986-183d-4764-8bd2-1d6b47f87d99"
 
# --- !!! SET THE TOTAL PRIZE POT HERE !!! ---
PRIZE_POT = 500000.00 # Example: $150,000
 
# --- !!! PASTE YOUR AUTH TOKEN HERE !!! ---
# Example format: 'auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
COOKIE = ''
 
# --- API and Request Details ---
# Construct the API URL using the REPO_ID
API_URL = f"https://cantina.xyz/api/v0/repositories/{REPO_ID}/findings"
 
PARAMS = {
    "limit": 2000, # Increased limit to fetch more/all findings if needed
    "with_events": "false",
    "with_files": "true",
    "duplicates": "true",
    "severity": "high,medium" # Fetch only High and Medium findings
}
 
BASE_POINTS = {
    "high": 10,
    "medium": 3
    # Low severity is not included based on the current rules provided
}
 
HEADERS = {
    # The Cookie will be set dynamically in the main execution block
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
    # Add other necessary headers from your original request if needed
}
# --- End Configuration ---
 
def calculate_scaled_points(base_points, n):
    """Calculates points scaled for n unique submitters."""
    if n <= 0:
        return 0
    if n == 1:
        return base_points # No scaling for unique findings
    # Formula: Base Points * 0.9^(n-1) / n
    scale_factor = math.pow(0.9, n - 1) / n
    return base_points * scale_factor
 
def fetch_findings(url, params, headers):
    """Fetches findings data from the API."""
    print(f"Fetching findings from {url}...")
    try:
        response = requests.get(url, params=params, headers=headers, timeout=60) # Increased timeout
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        print(f"Successfully fetched data (Status: {response.status_code}).")
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out after 60 seconds while fetching from {url}.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            # Try to decode JSON even on error to see if there's a message
            try:
                error_details = e.response.json()
                print(f"Response JSON: {error_details}")
            except json.JSONDecodeError:
                print(f"Response text: {e.response.text[:500]}...") # Print first 500 chars if not JSON
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response: {e}")
        # Check if response object exists before accessing text
        if 'response' in locals() and response is not None:
             print(f"Response text: {response.text[:500]}...")
        else:
             print("No response object available to show text.")
        return None
 
 
def process_payouts(data, prize_pot):
    """Processes findings data and calculates payouts."""
    if not data or 'findings' not in data:
        print("No findings data found or data is not in the expected format.")
        return
 
    findings = data['findings']
    print(f"\nProcessing {len(findings)} raw findings entries...")
 
    confirmed_originals = {} # Store original confirmed findings: {id: finding_data}
    all_valid_submissions = defaultdict(list) # {original_id: [(user_id, user_name, severity, finding_id), ...]}
    user_details = {} # {user_id: user_name}
 
    # --- Step 1: Identify all confirmed original findings ---
    for finding in findings:
        # Basic validation of finding structure
        if not isinstance(finding, dict):
            print(f"Warning: Skipping invalid finding entry (not a dictionary): {finding}")
            continue
        if finding.get('status') == 'confirmed':
            finding_id = finding.get('id')
            if finding_id:
                confirmed_originals[finding_id] = finding
 
    if not confirmed_originals:
        print("No 'confirmed' findings found in the dataset. Cannot process payouts.")
        return
 
    print(f"Found {len(confirmed_originals)} unique confirmed findings.")
 
    # --- Step 2: Group all valid submissions (confirmed originals and their valid duplicates) ---
    processed_finding_ids = set() # Track submission IDs to handle potential API duplicates
 
    for finding in findings:
         # Basic validation of finding structure
        if not isinstance(finding, dict):
            # Already warned in step 1, but good to have safeguard here too
            continue
 
        finding_id = finding.get('id')
        if not finding_id:
             print(f"Warning: Skipping finding entry with missing ID: {finding.get('title', 'N/A')}")
             continue
 
        # Avoid double-processing if the API returns the same finding multiple times
        if finding_id in processed_finding_ids:
             continue
        processed_finding_ids.add(finding_id)
 
        created_by_info = finding.get('createdBy')
        if not isinstance(created_by_info, dict):
            print(f"Warning: Skipping finding '{finding.get('title', finding_id)}' due to missing/invalid 'createdBy' info.")
            continue
 
        user_id = created_by_info.get('userId')
        user_name = created_by_info.get('username', 'N/A')
        status = finding.get('status')
        severity = finding.get('severity') # high or medium
 
        if not user_id:
            print(f"Warning: Skipping finding '{finding.get('title', finding_id)}' due to missing user ID.")
            continue
 
        if severity not in BASE_POINTS:
            # This filters out low severity or any other non-payable types
            continue
 
        # Store user details consistently
        if user_id not in user_details:
             user_details[user_id] = user_name
 
        original_id_to_process = None
        original_severity = None
 
        if status == 'confirmed':
            original_id_to_process = finding_id
            original_severity = severity
            # print(f"Debug: Confirmed finding {finding_id} by {user_name}, severity {severity}") # Debugging line
        elif status == 'duplicate':
            duplicate_of_info = finding.get('duplicateOf')
            # Ensure duplicateOf_info is valid and points to a CONFIRMED original
            if isinstance(duplicate_of_info, dict) and duplicate_of_info.get('id') in confirmed_originals:
                original_id_ref = duplicate_of_info.get('id')
                # Use the severity of the ORIGINAL confirmed finding for consistency
                original_severity = confirmed_originals[original_id_ref].get('severity')
                # Only process if the original's severity is payable
                if original_severity in BASE_POINTS:
                    original_id_to_process = original_id_ref
                    # print(f"Debug: Duplicate finding {finding_id} by {user_name} of confirmed {original_id_ref}, original severity {original_severity}") # Debugging line
            # else: it's a duplicate of a rejected/non-existent/non-confirmed original, or its original is low severity, so ignore it
 
        # Add to our processing list if it's valid and its original severity is payable
        if original_id_to_process and original_severity in BASE_POINTS:
             submission_tuple = (user_id, user_name, original_severity, finding_id)
             all_valid_submissions[original_id_to_process].append(submission_tuple)
        # else:
             # print(f"Debug: Skipped finding {finding_id} (status: {status}, severity: {severity})") # Debugging line
 
    # --- Step 3: Calculate points per user ---
    user_points = defaultdict(float)
    processed_vulnerabilities = defaultdict(list) # For detailed output later
 
    if not all_valid_submissions:
        print("No valid submissions found (confirmed or duplicates of confirmed with High/Medium severity).")
        return
 
    print(f"\nCalculating points based on {len(all_valid_submissions)} unique confirmed vulnerabilities...")
 
    for original_id, submissions in all_valid_submissions.items():
        if not submissions: # Should not happen based on previous logic, but safety check
            continue
 
        # Determine base points from the original severity (stored in tuple index 2)
        base_points = BASE_POINTS.get(submissions[0][2])
        if not base_points:
             print(f"Critical Error: Could not determine base points for vulnerability {original_id}. Severity was {submissions[0][2]}. Skipping.")
             continue
 
        # Find unique users for *this* specific vulnerability
        # Use user_id (index 0) to ensure uniqueness per user per vulnerability
        unique_users_for_vuln = set(sub[0] for sub in submissions)
        n = len(unique_users_for_vuln)
 
        # Calculate points per user for this vulnerability using the scaling formula
        points_per_user_for_this_vuln = calculate_scaled_points(base_points, n)
 
        # Award points to each unique user who submitted this vulnerability
        for user_id in unique_users_for_vuln:
            user_points[user_id] += points_per_user_for_this_vuln
 
        # Store details for reporting
        processed_vulnerabilities[original_id].append({
            'title': confirmed_originals.get(original_id,{}).get('title','N/A'), # Get title from original
            'severity': submissions[0][2],
            'submitters_count (n)': n,
            'base_points': base_points,
            'points_per_submitter': points_per_user_for_this_vuln,
            'submitters': sorted([user_details.get(uid, uid) for uid in unique_users_for_vuln]) # Sort usernames
        })
 
 
    # --- Step 4: Calculate total points and payouts ---
    total_points_awarded = sum(user_points.values())
 
    print("\n--- Points Calculation Summary (Per Vulnerability) ---")
    if not processed_vulnerabilities:
        print("No vulnerabilities qualified for point calculation.")
    else:
        # Sort vulnerabilities alphabetically by title for consistent reporting
        sorted_vuln_ids = sorted(processed_vulnerabilities.keys(), key=lambda vid: processed_vulnerabilities[vid][0]['title'])
 
        for orig_id in sorted_vuln_ids:
             details_list = processed_vulnerabilities[orig_id]
             details = details_list[0] # Should only be one entry per original_id now
             print(f"\nVulnerability: {details['title']} (Original ID: {orig_id})")
             print(f"  Severity: {details['severity']} (Base Points: {details['base_points']})")
             print(f"  Unique Submitters (n): {details['submitters_count (n)']}")
             print(f"  Points/Submitter (Scaled): {details['points_per_submitter']:.4f}")
             # print(f"  Submitters: {', '.join(details['submitters'])}")
 
 
    print("\n--- Payout Calculation ---")
    payout_data = []
    if total_points_awarded > 0:
        # Use Decimal for potentially better precision with currency? Or stick to float for simplicity? Float is fine for now.
        payout_per_point = prize_pot / total_points_awarded
        print(f"Total Prize Pot: ${prize_pot:,.2f}")
        print(f"Total Points Awarded: {total_points_awarded:.4f}")
        print(f"Payout per Point: ${payout_per_point:.4f}")
 
        for user_id, points in user_points.items():
            payout = points * payout_per_point
            user_name = user_details.get(user_id, f"ID:{user_id}") # Fallback to ID if name missing
            payout_data.append([user_name, f"{points:.4f}", f"${payout:,.2f}"])
    else:
        print("No points awarded across all users, cannot calculate payouts.")
 
    # --- Step 5: Display Results ---
    if payout_data:
        # Sort by payout amount descending
        payout_data.sort(key=lambda x: float(x[2].replace('$', '').replace(',', '')), reverse=True)
 
        # Add Totals row
        total_payout_calculated = sum(float(row[2].replace('$', '').replace(',', '')) for row in payout_data)
        payout_data.append(['---', '---', '---']) # Separator
        payout_data.append(['TOTALS', f"{total_points_awarded:.4f}", f"${total_payout_calculated:,.2f}"])
 
        print("\n--- Payout Summary Table (Per User) ---")
        print(tabulate(payout_data, headers=["Username", "Total Points", "Payout"], tablefmt="grid"))
 
        # Sanity check for payout sum vs prize pot
        if not math.isclose(total_payout_calculated, prize_pot, rel_tol=1e-4) and total_points_awarded > 0:
             # Small tolerance for floating point arithmetic
             print(f"\nNote: Total calculated payout (${total_payout_calculated:,.2f}) differs slightly from the prize pot (${prize_pot:,.2f}) due to rounding during calculations.")
        elif total_points_awarded == 0:
             pass # Already handled
        else:
             print(f"\nTotal calculated payout (${total_payout_calculated:,.2f}) matches the prize pot.")
 
 
    elif total_points_awarded == 0 and confirmed_originals:
         print("\nNo payouts calculated as no valid submissions earned points.")
    # If confirmed_originals was empty, it was handled earlier.
 
 
# --- Main Execution ---
if __name__ == "__main__":
    print("Starting payout calculation script...")
 
    # --- Input Validation ---
    valid_config = True
    if 'YOUR_REPOSITORY_ID_HERE' in REPO_ID or not REPO_ID.strip():
        print("\nError: Configuration incomplete.")
        print("Please set the REPO_ID variable with the correct repository ID.")
        valid_config = False
 
    if 'PASTE_YOUR_FULL_AUTH_TOKEN_COOKIE_STRING_HERE' in COOKIE or not COOKIE.strip().startswith('auth_token='):
        print("\nError: Configuration incomplete.")
        print("Please replace 'PASTE_YOUR_FULL_AUTH_TOKEN_COOKIE_STRING_HERE' with your actual auth_token in the COOKIE variable.")
        valid_config = False
 
    if PRIZE_POT <= 0:
         print("\nWarning: PRIZE_POT is set to zero or negative. Payouts will be $0.")
         # Allow execution, but payouts will be zero.
 
    if valid_config:
        print(f"Repository ID: {REPO_ID}")
        print(f"Prize Pot: ${PRIZE_POT:,.2f}")
 
        # Set the cookie in the headers *after* validation
        HEADERS['Cookie'] = COOKIE
 
        # --- Fetch Data ---
        api_data = fetch_findings(API_URL, PARAMS, HEADERS)
 
        # --- Process Data ---
        if api_data:
            process_payouts(api_data, PRIZE_POT)
        else:
            print("\nExiting script due to data fetching error or empty data.")
    else:
        print("\nExiting script due to configuration errors.")
 
    print("\nScript finished.")
