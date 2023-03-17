#include <global.hpp>

#include <Havoc/Havoc.hpp>

#include <UserInterface/Widgets/SessionGraph.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/ProcessList.hpp>
#include <UserInterface/Widgets/FileBrowser.hpp>

#include <Util/ColorText.h>

#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

#include <math.h>

#include <QKeyEvent>
#include <QRandomGenerator>
#include <QStyle>
#include <QStyleOptionGraphicsItem>
#include <QGraphicsSceneContextMenuEvent>
#include <QPixmap>

using namespace HavocNamespace::Util;

GraphWidget::GraphWidget( QWidget* parent ) : QGraphicsView( parent )
{
    GraphScene = new QGraphicsScene( this );
    GraphScene->setItemIndexMethod( QGraphicsScene::BspTreeIndex );

    setScene( GraphScene );
    setCacheMode( CacheBackground );
    setViewportUpdateMode( BoundingRectViewportUpdate );
    setRenderHint( QPainter::Antialiasing );
    setTransformationAnchor( AnchorUnderMouse );
    scaleView( qreal( 1 ) );

    MainNode = new Member {
        .Name = "MainNode",
        .Node = new Node( NodeItemType::MainNode, QString(), this ),
    };

    MainNode->Node->Session = {};

    GraphScene->addItem( MainNode->Node );

    MainNode->Node->setPos( 500, 100 );

    NodeList.push_back( MainNode );
}

Node* GraphWidget::GraphNodeAdd( SessionItem Session )
{
    auto item = new Node(
        NodeItemType::Session,
        Session.Name + " " + Session.Process + "\\" + Session.PID +
        " [" + Session.Computer + "\\" + Session.User + "]",
        this
    );

    item->NodeEdge = new Edge( MainNode->Node, item, QColor( HavocNamespace::Util::ColorText::Colors::Hex::Green ) );
    item->NodeID   = Session.Name;
    item->Session  = Session;

    auto member = new Member {
        .Name = Session.Name,
        .Node = item,
    };

    GraphScene->addItem( item );
    GraphScene->addItem( item->NodeEdge );

    NodeList.push_back( member );

    return item;
}

void GraphWidget::GraphNodeRemove( SessionItem Session )
{
    for ( int i = 0; i < NodeList.size(); i++ )
    {
        if ( Session.Name.compare( NodeList[ i ]->Name ) == 0 )
        {
            GraphScene->removeItem( NodeList[ i ]->Node->NodeEdge );
            GraphScene->removeItem( NodeList[ i ]->Node );

            /* delete NodeList[ i ]->Node->NodeEdge;
            delete NodeList[ i ]->Node;
            delete NodeList[ i ]; */

            return;
        }
    }
}

void GraphWidget::GraphPivotNodeAdd( QString AgentID, SessionItem Session )
{
    auto item = new Node(
        NodeItemType::Session,
        Session.Name + " " + Session.Process + "\\" + Session.PID +
        " [" + Session.Computer + "\\" + Session.User + "]",
        this
    );

    item->Session = Session;

    GraphScene->addItem( item );

    const auto items = scene()->items();

    for ( QGraphicsItem* g_item : items )
    {
        if ( qgraphicsitem_cast<Node*>( g_item ) )
        {
            auto i = qgraphicsitem_cast<Node*>( g_item );
            if ( i->NodeID.compare( AgentID ) == 0 )
            {
                item->NodeID   = Session.Name;
                item->NodeEdge = new Edge( i, item, QColor( HavocNamespace::Util::ColorText::Colors::Hex::Purple ) );

                GraphScene->addItem( item->NodeEdge );
                return;
            }
        }
    }

    spdlog::error( "Parent AgentID {} not found for {}", AgentID.toStdString(), Session.Name.toStdString() );
}

void GraphWidget::GraphPivotNodeDisconnect( QString AgentID )
{
    const auto items = GraphScene->items();

    for ( QGraphicsItem* g_item : items )
    {
        if ( qgraphicsitem_cast<Edge*>( g_item ) )
        {
            auto i = qgraphicsitem_cast<Edge*>( g_item );
            if ( i->dest->NodeID.compare( AgentID ) == 0 )
            {
                i->dest->Disconnected = true;
                i->Color( QColor( HavocNamespace::Util::ColorText::Colors::Hex::Red ) );

                i->dest->update();
                i->source->update();

                return;
            }
        }
    }
}

void GraphWidget::GraphPivotNodeReconnect( QString ParentAgentID, QString ChildAgentID )
{
    const auto items = GraphScene->items();

    for ( QGraphicsItem* g_item : items )
    {
        if ( qgraphicsitem_cast<Edge*>( g_item ) )
        {
            auto i = qgraphicsitem_cast<Edge*>( g_item );
            if ( i->dest->NodeID.compare( ChildAgentID ) == 0 )
            {
                GraphScene->addItem( new Edge( GraphNodeGet( ParentAgentID ), i->dest, QColor( HavocNamespace::Util::ColorText::Colors::Hex::Purple ) ) );
                GraphScene->removeItem( i );

                // TODO: somehow remove/free i (Edge*)
                // i->source = GraphNodeGet( ParentAgentID );
                // i->dest->Disconnected = false;
                // i->Color( QColor( HavocNamespace::Util::ColorText::Colors::Hex::Purple ) );

                // i->dest->update();
                // i->source->update();

                return;
            }
        }
    }
}

void GraphWidget::itemMoved()
{
    if ( ! timerId )
        timerId = startTimer( 1000 / 25 );
}

void GraphWidget::keyPressEvent( QKeyEvent* event )
{
    switch ( event->key( ) )
    {
        case Qt::Key_Plus:
            zoomIn();
            break;

        case Qt::Key_Minus:
            zoomOut();
            break;

        default:
            QGraphicsView::keyPressEvent( event );
    }
}

void GraphWidget::timerEvent( QTimerEvent* event )
{
    Q_UNUSED( event );

    const auto  items       = scene()->items();
    auto        nodes       = QVector<Node*>();
    bool        itemsMoved  = false;

    for ( QGraphicsItem* item : items )
    {
        if ( Node* node = qgraphicsitem_cast<Node*>( item ) )
            nodes << node;
    }

    for ( Node* node : qAsConst( nodes ) )
        node->calculateForces();

    for ( Node* node : qAsConst( nodes ) )
    {
        if ( node->advancePosition() )
            itemsMoved = true;
    }

    if ( ! itemsMoved )
    {
        killTimer( timerId );
        timerId = 0;
    }
}

void GraphWidget::resizeEvent( QResizeEvent* event )
{
    scene()->setSceneRect( 0, 0, event->size().width(), event->size().height() );

    QGraphicsView::resizeEvent( event );
}

void GraphWidget::wheelEvent( QWheelEvent* event )
{
    scaleView( pow( 2., event->angleDelta().y() / 500.0 ) );
}

void GraphWidget::drawBackground( QPainter* painter, const QRectF& rect )
{
    Q_UNUSED( rect );

    // Shadow
    auto sceneRect  = this->sceneRect();
    auto gradient   = QLinearGradient( sceneRect.topLeft(), sceneRect.bottomRight() );
    auto Background = HavocNamespace::Util::ColorText::Colors::Hex::Background;

    gradient.setColorAt( 0, QColor( Background ) );

    painter->fillRect( rect.intersected( sceneRect ), gradient );
    painter->setBrush( Qt::NoBrush );
    painter->drawRect( sceneRect );
}

void GraphWidget::scaleView( qreal scaleFactor )
{
    qreal factor = transform().scale( scaleFactor, scaleFactor ).mapRect( QRectF( 0, 0, 1, 1 ) ).width();
    if ( factor < 1 || factor > 50 )
        return;

    scale( scaleFactor, scaleFactor );
}

void GraphWidget::shuffle()
{
    const auto items = scene()->items();

    for ( QGraphicsItem* item : items )
    {
        if ( qgraphicsitem_cast<Node*>( item ) )
            item->setPos( -150 + QRandomGenerator::global()->bounded( 300 ), -150 + QRandomGenerator::global()->bounded( 300 ) );
    }
}

void GraphWidget::zoomIn()
{
    scaleView( qreal( 1.2 ) );
}

void GraphWidget::zoomOut()
{
    scaleView( 1 / qreal( 1.2 ) );
}

Node *GraphWidget::GraphNodeGet( QString AgentID )
{
    const auto items = GraphScene->items();

    for ( QGraphicsItem* g_item : items )
    {
        if ( qgraphicsitem_cast<Node*>( g_item ) )
        {
            auto i = qgraphicsitem_cast<Node*>( g_item );
            if ( i->NodeID.compare( AgentID ) == 0 )
            {
                return i;
            }
        }
    }
}

// ==================================================
// =================== Edge Class ===================
// ==================================================
Edge::Edge( Node* sourceNode, Node* destNode, QColor Color )
    : source( sourceNode ), dest( destNode ), color( Color )
{
    setAcceptedMouseButtons( Qt::NoButton );

    source->addEdge( this );
    dest->addEdge( this );

    adjust();
}

Node* Edge::sourceNode() const
{
    return source;
}

Node* Edge::destNode() const
{
    return dest;
}

void Node::contextMenuEvent( QGraphicsSceneContextMenuEvent* event )
{
    if ( NodeType == NodeItemType::MainNode )
        return;

    auto MenuStyle = QString(
            "QMenu {"
            "    background-color: #282a36;"
            "    color: #f8f8f2;"
            "    border: 1px solid #44475a;"
            "}"
            "QMenu::separator {"
            "    background: #44475a;"
            "}"
            "QMenu::item:selected {"
            "    background: #44475a;"
            "}"
            "QAction {"
            "    background-color: #282a36;"
            "    color: #f8f8f2;"
            "}"
    );

    auto Agent     = Util::SessionItem{};

    for ( auto s : HavocX::Teamserver.Sessions )
    {
        if ( s.Name.compare( NodeID ) == 0 )
        {
            Agent = s;
            break;
        }
    }

    auto seperator  = new QAction();
    auto seperator2 = new QAction();
    auto seperator3 = new QAction();
    auto seperator4 = new QAction();

    seperator->setSeparator( true );
    seperator2->setSeparator( true );
    seperator3->setSeparator( true );
    seperator4->setSeparator( true );

    auto SessionMenu     = QMenu();
    auto SessionExplorer = QMenu( "Explorer" );

    SessionExplorer.addAction( "Process List" );
    SessionExplorer.addAction( "File Explorer" );
    SessionExplorer.setStyleSheet( MenuStyle );

    SessionMenu.addAction( "Interact" );
    SessionMenu.addAction( seperator );

    if ( Agent.MagicValue == DemonMagicValue )
    {
        SessionMenu.addAction( SessionExplorer.menuAction() );
        SessionMenu.addAction( seperator2 );
    }

    if ( Agent.Marked.compare( "Dead" ) != 0 )
        SessionMenu.addAction( "Mark as Dead" );
    else
        SessionMenu.addAction( "Mark as Alive" );

    SessionMenu.addAction( "Export" );
    SessionMenu.addAction( seperator3 );
    SessionMenu.addAction( "Remove" );

    if ( Agent.MagicValue == DemonMagicValue )
    {
        auto ExitMenu = QMenu( "Exit" );

        ExitMenu.addAction( "Thread" );
        ExitMenu.addAction( "Process" );
        ExitMenu.setStyleSheet( MenuStyle );

        SessionMenu.addAction( ExitMenu.menuAction() );
    }
    else
    {
        SessionMenu.addAction( "Exit" );
    }

    SessionMenu.setStyleSheet( MenuStyle );

    auto *action = SessionMenu.exec( event->screenPos() );

    if ( action )
    {
        for ( auto & Session : HavocX::Teamserver.Sessions )
        {
            // TODO: make that on Session receive
            if ( Session.InteractedWidget == nullptr )
            {
                Session.InteractedWidget                 = new UserInterface::Widgets::DemonInteracted;
                Session.InteractedWidget->SessionInfo    = Session;
                Session.InteractedWidget->TeamserverName = HavocX::Teamserver.Name;
                Session.InteractedWidget->setupUi( new QWidget );
            }

            if ( Session.Name.compare( NodeID ) == 0 )
            {
                if ( action->text().compare( "Interact" ) == 0 )
                {
                    auto tabName = "[" + Session.Name + "] " + Session.User + "/" + Session.Computer;
                    for ( int i = 0 ; i < HavocX::Teamserver.TabSession->tabWidget->count(); i++ )
                    {
                        if ( HavocX::Teamserver.TabSession->tabWidget->tabText( i ) == tabName )
                        {
                            HavocX::Teamserver.TabSession->tabWidget->setCurrentIndex( i );
                            return;
                        }
                    }

                    HavocX::Teamserver.TabSession->NewBottomTab( Session.InteractedWidget->DemonInteractedWidget, tabName.toStdString() );
                    Session.InteractedWidget->lineEdit->setFocus();
                }
                else if ( action->text().compare( "Mark as Dead" ) == 0 )
                {
                    auto Marked = QString();
                    Marked = "Dead";
                    HavocApplication->HavocAppUI.MarkSessionAs( Session, Marked );
                }
                else if ( action->text().compare( "Mark as Alive" ) == 0 )
                {
                    auto Marked = QString();
                    Marked = "Alive";
                    HavocApplication->HavocAppUI.MarkSessionAs( Session, Marked );
                }
                else if ( action->text().compare( "Mark as Dead" ) == 0 || action->text().compare( "Mark as Alive" ) == 0 )
                {
                    for ( int i = 0; i <  HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
                    {
                        auto AgentID = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                        if ( AgentID.compare( NodeID ) == 0 )
                        {
                            auto Package = new Util::Packager::Package;

                            Package->Head = Util::Packager::Head_t {
                                    .Event= Util::Packager::Session::Type,
                                    .User = HavocX::Teamserver.User.toStdString(),
                                    .Time = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
                            };

                            auto Marked = QString();

                            if ( action->text().compare( "Mark as Alive" ) == 0 )
                            {
                                Marked = "Alive";
                                Session.Marked = Marked;

                                auto Icon = ( Session.Elevated.compare( "true" ) == 0 ) ?
                                            WinVersionIcon( Session.OS, true ) :
                                            WinVersionIcon( Session.OS, false );

                                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( Icon );

                                for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                                {
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Foreground ) );
                                }
                            }
                            else if ( action->text().compare( "Mark as Dead" ) == 0 )
                            {
                                Marked = "Dead";
                                Session.Marked = Marked;

                                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );

                                for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                                {
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
                                }
                            }

                            Package->Body = Util::Packager::Body_t {
                                    .SubEvent = Util::Packager::Session::MarkAs,
                                    .Info = {
                                            { "AgentID", AgentID.toStdString() },
                                            { "Marked",  Marked.toStdString() },
                                    }
                            };

                            HavocX::Connector->SendPackage( Package );
                        }
                    }
                }
                else if ( action->text().compare( "Export" ) == 0 )
                {
                    Session.Export();
                }
                else if ( action->text().compare( "Remove" ) == 0 )
                {
                    // TODO: Add a function to Session item that removes itself from the session table and graph.
                    for ( int i = 0; i < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
                    {
                        auto Row = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                        if ( Row.compare( Session.Name ) == 0 )
                        {
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->removeRow( i );
                        }
                    }

                    delete NodeEdge;
                    delete this;
                }
                else if ( action->text().compare( "Thread" ) == 0 || action->text().compare( "Process" ) == 0 )
                {
                    Session.InteractedWidget->DemonCommands->Execute.Exit( Util::gen_random( 8 ).c_str(), action->text().toLower() );
                }
                if ( Session.MagicValue == DemonMagicValue )
                {
                    if ( action->text().compare( "Process List" ) == 0 )
                    {
                        auto TabName = QString( "[" + NodeID + "] Process List" );

                        if ( Session.ProcessList == nullptr )
                        {
                            Session.ProcessList = new UserInterface::Widgets::ProcessList;
                            Session.ProcessList->setupUi( new QWidget );
                            Session.ProcessList->Session = Session;
                            Session.ProcessList->Teamserver = HavocX::Teamserver.Name;

                            HavocX::Teamserver.TabSession->NewBottomTab( Session.ProcessList->ProcessListWidget, TabName.toStdString() );
                        }
                        else
                        {
                            HavocX::Teamserver.TabSession->NewBottomTab( Session.ProcessList->ProcessListWidget, TabName.toStdString() );
                        }

                        Session.InteractedWidget->DemonCommands->Execute.ProcList( Util::gen_random( 8 ).c_str(), true );
                    }
                    else if ( action->text().compare( "File Explorer" ) == 0 )
                    {
                        auto TabName = QString( "[" + NodeID + "] File Explorer" );

                        if ( Session.FileBrowser == nullptr )
                        {
                            Session.FileBrowser = new FileBrowser;
                            Session.FileBrowser->setupUi( new QWidget );
                            Session.FileBrowser->SessionID = Session.Name;

                            HavocX::Teamserver.TabSession->NewBottomTab( Session.FileBrowser->FileBrowserWidget, TabName.toStdString(), "" );
                        }
                        else
                        {
                            HavocX::Teamserver.TabSession->NewBottomTab( Session.FileBrowser->FileBrowserWidget, TabName.toStdString(), "" );
                        }

                        Session.InteractedWidget->DemonCommands->Execute.FS( Util::gen_random( 8 ).c_str(), "dir;ui", "." );
                    }
                }

            }
        }

    }

    delete seperator;
    delete seperator2;
    delete seperator3;
    delete seperator4;
}

void Edge::adjust()
{
    if ( ! source || ! dest )
        return;

    auto line   = QLineF( mapFromItem( source, 0, 0 ), mapFromItem( dest, 0, 0 ) );
    auto length = line.length();

    prepareGeometryChange();

    if ( length > qreal( 20. ) )
    {
        auto edgeSpace  = 50;
        auto edgeOffset = QPointF( ( line.dx() * edgeSpace ) / length, ( line.dy() * edgeSpace ) / length );

        sourcePoint = line.p1() + edgeOffset;
        destPoint   = line.p2() - edgeOffset;
    }
    else
    {
        sourcePoint = destPoint = line.p1();
    }
}

QRectF Edge::boundingRect() const
{
    if ( ! source || ! dest )
        return QRectF();

    qreal penWidth  = 1;
    qreal extra     = ( penWidth + arrowSize ) / 2.0;

    return QRectF( sourcePoint, QSizeF( destPoint.x() - sourcePoint.x(), destPoint.y() - sourcePoint.y()) )
            .normalized()
            .adjusted( -extra, -extra, extra, extra );
}

void Edge::paint( QPainter* painter, const QStyleOptionGraphicsItem*, QWidget* )
{
    if ( ! source || ! dest )
        return;

    auto line = QLineF( sourcePoint, destPoint );
    if ( qFuzzyCompare( line.length(), qreal( 0. ) ) )
        return;

    // Draw the arrows
    auto angle         = std::atan2( -line.dy(), line.dx() );

    auto sourceArrowP1 = sourcePoint + QPointF( sin( angle + M_PI / 3 ) * arrowSize, cos( angle + M_PI / 3 ) * arrowSize );
    auto sourceArrowP2 = sourcePoint + QPointF( sin( angle + M_PI - M_PI / 3 ) * arrowSize, cos( angle + M_PI - M_PI / 3 ) * arrowSize );
    auto destArrowP1   = destPoint   + QPointF( sin( angle - M_PI / 3 ) * arrowSize, cos( angle - M_PI / 3 ) * arrowSize );
    auto destArrowP2   = destPoint   + QPointF( sin( angle - M_PI + M_PI / 3 ) * arrowSize, cos( angle - M_PI + M_PI / 3 ) * arrowSize );

    // Draw the line itself
    painter->setPen( QPen( color, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin ) );
    painter->drawLine( line );
    painter->setBrush( color );

    if ( source->NodeType == NodeItemType::MainNode )
        painter->drawPolygon( QPolygonF() << line.p1() << sourceArrowP1 << sourceArrowP2 );
    else
        painter->drawPolygon( QPolygonF() << line.p2() << destArrowP1 << destArrowP2 );
}

void Edge::Color( QColor color )
{
    this->color = color;
}

// ==================================================
// =================== Node Class ===================
// ==================================================
Node::Node( NodeItemType NodeType, QString NodeLabel, GraphWidget* graphWidget ) : graph( graphWidget )
{
    this->NodeType  = NodeType;
    this->NodeLabel = NodeLabel;

    if ( NodeType == NodeItemType::MainNode )
        this->NodePainterSize = QRectF( -40, -50, 80, 80 );
    else
        this->NodePainterSize = QRectF( -150, -150, 400, 230 );

    setFlag( ItemIsMovable );
    setFlag( ItemSendsGeometryChanges );
    setCacheMode( DeviceCoordinateCache );
    setZValue( -1 );
}

QRectF Node::boundingRect() const
{
    return NodePainterSize;
}

void Node::addEdge( Edge* edge )
{
    edgeList << edge;
    edge->adjust();
}

QVector<Edge*> Node::edges() const
{
    return edgeList;
}

void Node::calculateForces()
{
    auto xvel = qreal( 0 );
    auto yvel = qreal( 0 );

    if ( ! scene() || scene()->mouseGrabberItem() == this )
    {
        newPos = pos();
        return;
    }

    if ( qAbs( xvel ) < 0.1 && qAbs( yvel ) < 0.1 )
        xvel = yvel = 0;

    auto sceneRect = scene()->sceneRect();

    newPos = pos() + QPointF( xvel, yvel );
    newPos.setX( qMin( qMax( newPos.x(), sceneRect.left() + 10 ), sceneRect.right()  - 10 ) );
    newPos.setY( qMin( qMax( newPos.y(), sceneRect.top()  + 10 ), sceneRect.bottom() - 10 ) );
}

void Node::mouseMoveEvent( QGraphicsSceneMouseEvent* event )
{
    QGraphicsItem::mouseMoveEvent( event );
}

bool Node::advancePosition()
{
    if ( newPos == pos() )
        return false;

    setPos( newPos );
    return true;
}

QPainterPath Node::shape() const
{
    auto path = QPainterPath();

    path.addEllipse( NodePainterSize );

    return path;
}

void Node::paint( QPainter *painter, const QStyleOptionGraphicsItem* option, QWidget* )
{
    if ( NodeType == NodeItemType::Nothing )
    {
        return;
    }
    else if ( NodeType == NodeItemType::MainNode )
    {
        auto image1 = QImage( ":/images/SessionHavoc" );

        painter->drawImage( NodePainterSize, image1 );

        return;
    }
    else if ( NodeType == NodeItemType::Session )
    {
        auto text   = NodeLabel.split( " " );
        auto image1 = ( Session.Elevated.compare( "true" ) == 0 ) ?
                      WinVersionImage( Session.OS, true ) :
                      WinVersionImage( Session.OS, false );

        if ( Disconnected )
        {
            image1 = GrayScale( image1 );
        }
        else
        {
            for ( auto& session : HavocX::Teamserver.Sessions )
            {
                if ( session.Name.compare( NodeID ) == 0 )
                {
                    if ( session.Marked.compare( "Dead" ) == 0 )
                        image1 = GrayScale( image1 );
                }
            }
        }

        painter->drawImage( QRectF( -40, -35, 90, 90 ), image1 );
        painter->setPen( QPen( Qt::white ) );
        painter->drawText( -90, 60, text[ 0 ] + " @ " + text[ 1 ] );
        painter->drawText( -80, 75, text[ 2 ] );

        return;
    }
    else
        return;
}

QVariant Node::itemChange( GraphicsItemChange change, const QVariant& value )
{
    switch ( change )
    {
        case ItemPositionHasChanged:
        {
            for ( Edge* edge : qAsConst( edgeList ) )
                edge->adjust();

            graph->itemMoved();

            break;
        }
        default: break;
    };

    return QGraphicsItem::itemChange( change, value );
}

void Node::mousePressEvent( QGraphicsSceneMouseEvent* event )
{
    update();
    QGraphicsItem::mousePressEvent( event );
}

void Node::mouseReleaseEvent( QGraphicsSceneMouseEvent* event )
{
    update();
    QGraphicsItem::mouseReleaseEvent( event );
}