const generateHimeNumber = (userType) => {
	const prefix = userType === 'anonymous' ? '2' : '1';
	const uuid = Math.floor(10000000 + Math.random() * 90000000); // 8 digits
	return `${prefix}-${uuid}`;
};

module.exports = generateHimeNumber;
