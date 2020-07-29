const member = (sequelize, DataTypes) => {
    const Member = sequelize.define('member', {
	seq: {
	    type: DataTypes.INTEGER,
	    unique: false,
	    allowNull: false,
	    validate: {
		notEmpty: true,
	    },
	},
	challenge: {
	    type: DataTypes.TEXT,
	    unique: true,
	    allowNull: false,
	    validate: {
		notEmpty: true,
	    },
	},     
    });

    Member.associate = models => {
	Member.belongsTo(models.Group);
    };

    Member.findByChallenge = async chal => {
	let member = await Member.findOne({
	    where: { challenge: chal },
	});
	return member;
    };    
    
    return Member;
};

export default member;
