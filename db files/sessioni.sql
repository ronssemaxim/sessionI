SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

CREATE SCHEMA IF NOT EXISTS `sessioni` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci ;
USE `sessioni` ;

-- -----------------------------------------------------
-- Table `sessioni`.`sessioniId`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `sessioni`.`sessioniId` ;

CREATE  TABLE IF NOT EXISTS `sessioni`.`sessioniId` (
  `id` INT(255) NOT NULL AUTO_INCREMENT ,
  `key` VARCHAR(45) NOT NULL ,
  `ip` VARCHAR(45) NOT NULL ,
  `expires` DATETIME NOT NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `key_UNIQUE` (`key` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `sessioni`.`vars`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `sessioni`.`vars` ;

CREATE  TABLE IF NOT EXISTS `sessioni`.`vars` (
  `varId` INT(255) NOT NULL AUTO_INCREMENT ,
  `sessioniId` INT(255) NOT NULL ,
  `varName` TEXT NOT NULL ,
  `varValue` TEXT NULL ,
  `expires` DATETIME NOT NULL ,
  `domain` VARCHAR(255) NULL ,
  `path` TEXT NULL ,
  `secure` TINYINT(1) NOT NULL DEFAULT 1 ,
  INDEX `fk_vars_sessionId_idx` (`sessioniId` ASC) ,
  PRIMARY KEY (`varId`) ,
  CONSTRAINT `fk_vars_sessionId`
    FOREIGN KEY (`sessioniId` )
    REFERENCES `sessioni`.`sessioniId` (`id` )
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;

USE `sessioni` ;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
