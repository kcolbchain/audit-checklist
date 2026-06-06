"""Custom Slither detectors for audit-checklist patterns."""
from .custom_access_control import CustomAccessControlDetector
from .custom_flash_loan import CustomFlashLoanDetector
from .custom_governance import CustomGovernanceDetector
from .custom_oracle import CustomOracleDetector
from .custom_reentrancy import CustomReentrancyDetector
from .custom_upgrade_gap import CustomUpgradeGapDetector
from .erc20_approval_race import ERC20ApprovalRaceDetector
