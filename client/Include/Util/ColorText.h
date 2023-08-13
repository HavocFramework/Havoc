#ifndef HAVOC_COLORTEXT_H
#define HAVOC_COLORTEXT_H

#include <global.hpp>

class HavocNamespace::Util::ColorText {
public:
    struct Colors {
        struct Hex {
            static QString Background;
                static QString Foreground;
            static QString CurrentLine;
            static QString Comment;

            static QString Cyan;
            static QString Green;
            static QString Orange;
            static QString Pink;
            static QString Purple;
            static QString Red;
            static QString Yellow;

            static QString SessionCyan;
            static QString SessionGreen;
            static QString SessionOrange;
            static QString SessionPink;
            static QString SessionPurple;
            static QString SessionRed;
            static QString SessionYellow;
        };
    };

    static void SetDraculaDark();
    static void SetDraculaLight();

    static QString Color(const QString& color, const QString& text);
    static QString Background(const QString&);
    static QString Foreground(const QString&);
    static QString Comment(const QString&);
    static QString Cyan(const QString&);
    static QString Green(const QString&);
    static QString Orange(const QString&);
    static QString Pink(const QString&);
    static QString Purple(const QString&);
    static QString Red(const QString&);
    static QString Yellow(const QString&);

    static QString Underline(const QString& text);
    static QString UnderlineBackground(const QString& text);
    static QString UnderlineForeground(const QString& text);
    static QString UnderlineComment(const QString& text);
    static QString UnderlineCyan(const QString& text);
    static QString UnderlineGreen(const QString& text);
    static QString UnderlineOrange(const QString& text);
    static QString UnderlinePink(const QString& text);
    static QString UnderlinePurple(const QString& text);
    static QString UnderlineRed(const QString& text);
    static QString UnderlineYellow(const QString& text);

    static QString Bold(const QString& text);
};

#endif //HAVOC_COLORTEXT_H
